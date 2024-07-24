# Pwn2Own Automotive 2024 CHARX Exploit

This exploit was submitted successfully against the Phoenix Contact CHARX SEC-3100 during Pwn2Own Automotive 2024.

An accompanying [blog post](https://blog.ret2.io/2024/07/17/pwn2own-auto-2024-charx-bugs/) covers some of our research process and details on the vulnerabilities found,
with a [follow-up post](https://blog.ret2.io/2024/07/24/pwn2own-auto-2024-charx-exploit/) on the actual exploitation techniques used.

Running the exploit requires:
- CHARX running firmware 1.5.0
- python3 / scapy
- scapy will require root privileges to send raw packets
- attacker machine plugged directly into the CHARX ETH1 ethernet port
- attacker machine configured with IP 192.168.4.2

Once the exploit succeeds, there will be an interactive connect-back shell running as the `charx-ca` user (for the ControllerAgent service).
