import argparse, socket, os, sys, json

parser = argparse.ArgumentParser()
parser.add_argument("iface", help="interface connected to charx eth1")
args = parser.parse_args()

from scapy.arch import get_if_addr
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.sendrecv import srp1

print("testing TCP connection to 192.168.4.1 port 4444")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.connect(("192.168.4.1", 4444))
sock.send(b"A\0\n")
sock.settimeout(5)
resp = sock.recv(0x1000)
expected = b'{"error":"contentNotParsable"}\n'
if resp != expected:
    raise Exception("unexpected TCP response: %s\n  expected: %s"%(resp, expected))
print("checking agent version")
sock.send(b'{"operationName":"configAccess","operationId":1,"deviceUid":"root","operationParameters":{"accessType":"read","configurationParams":[{"name":"AgentVersion"}]}}\n')
resp = sock.recv(0x1000)
version = json.loads(resp)["operationResult"]["configurationParams"]["AgentVersion"]["value"]
print("agent version: %s"%version)
if not version.startswith("1.5.0"):
    raise Exception("version is out of data, expected v1.5.0 got: %s"%version)
sock.close()
print("TCP looks good")

print("checking interface IP")
ip = get_if_addr(args.iface)
if ip != "192.168.4.2":
    s = "interface %s should have static ip 192.168.4.2, is: %s"%(args.iface, ip)
    if ip == "0.0.0.0":
        s += " (does the interface exist?)"
    raise Exception(s)

print("trying to send ARP")
arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst="192.168.4.1")
res = srp1(arp, iface=args.iface)
arpmac = res.payload.hwsrc
print("got MAC %s"%arpmac)
arpmac2 = getmacbyip("192.168.4.1")
print("getmacbyip says %s"%arpmac2)
if arpmac != arpmac2:
    raise Exception("getmacbyip / raw ARP mismatch??")
if not arpmac.startswith("a8:74:1d"):
    raise Exception("OUI doesn't match Phoenix Contact, is the MAC right?")

if os.name == "nt":
    print("Windows detected, adding firewall rules just in case, for %s"%sys.executable)
    print("trying to delete duplicate old rules")
    os.system('netsh advfirewall firewall delete rule name=pwn2own-charx')
    ret = os.system('netsh advfirewall firewall add rule name=pwn2own-charx enable=yes dir=in action=allow protocol=tcp edge=deferuser program="%s"'%sys.executable)
    if ret:
        raise Exception("adding tcp rule failed")
    ret = os.system('netsh advfirewall firewall add rule name=pwn2own-charx enable=yes dir=in action=allow protocol=udp edge=deferuser program="%s"'%sys.executable)
    if ret:
        raise Exception("adding udp rule failed")
    print("firewall rules added")
    print("rules can be deleted later with netsh advfirewall firewall delete rule name=pwn2own-charx")

print("all looks good")
