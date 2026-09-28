```bash
Hide your real scan among fake sources
nmap -D decoy1,decoy2,decoy3,ME,decoy4 <target>

# Random decoys
nmap -D RND:10 <target>
```


### The core idea: hiding your real SYN among a crowd of fake ones

Decoy scan doesn't try to make your traffic invisible (like fragmentation) or make someone else's machine do the talking for you (like idle scan). Instead it does something conceptually simpler: **it sends the same SYN packet from many different spoofed source IPs simultaneously — including your real one — so the target's logs show a dozen "attackers" at once, and your real IP is just one indistinguishable entry in that crowd.**

bash

```bash
nmap -D decoy1,decoy2,decoy3,ME,decoy4 <target>
```

### What actually goes out on the wire

For every port probed, nmap sends **multiple SYN packets** to the target — one appearing to come from each decoy IP, plus one from your real IP (position controlled by where you put `ME` in the list, or nmap inserts it randomly if you omit `ME`):

```
Target receives, all within a tiny time window:
  SYN → from decoy1 (spoofed)
  SYN → from decoy2 (spoofed)
  SYN → from decoy3 (spoofed)
  SYN → from YOU (real)
  SYN → from decoy4 (spoofed)
```

The target responds to _all_ of them, because as far as it knows, five different hosts all just asked the same question at the same time:

```
Target sends SYN-ACK/RST back to decoy1, decoy2, decoy3, YOU, decoy4
```

You alone actually receive and process a reply (the decoys' replies go to _them_, since that's genuinely their IP — they didn't ask for anything, so if they get a stray SYN-ACK, they just RST it, like the zombie did in idle scan).

### What "bypass" even means here — and this is important

Unlike fragmentation or idle scan, **decoy scan doesn't defeat any firewall rule at all.** If port 22 is blocked for outside SYNs, it's blocked for all six sources — decoys and you alike, equally. Decoy scanning doesn't get through anything a plain scan wouldn't. It's not evasion of _detection logic_ — it's evasion of **attribution**.

So the property it actually gives you is: _if_ the target/IDS logs "who scanned us," a defender sees six IPs hitting every port in the same pattern, at the same moment, and has no principled way to tell which of the six was the real attacker just from the traffic alone. Your job in a decoy scan isn't "get through a rule" — it's "become unidentifiable in a crowd."

This is a meaningfully different threat model from everything else we've covered, and worth being precise about for your project writeup — decoys don't belong in the same bucket as "firewall bypass" the way fragmentation/idle scan do. They're **attribution evasion**, not **rule evasion**.

### Choosing decoys — this is where it gets easy to do wrong

bash

```bash
nmap -D decoy1,decoy2,decoy3,ME,decoy4 <target>
```

For this to work as intended, your decoys need to be:

1. **Actually alive/reachable** — if a decoy IP doesn't exist or is unreachable, the target's SYN-ACK/RST replies to it will just vanish into the void, which is fine functionally, but...
2. **Not surprised by the reply** — if a decoy is a _real, active machine_ that gets an unsolicited SYN-ACK, its TCP stack will auto-respond with a RST, same as we saw with the zombie. That's expected and harmless to your scan.
3. **Ideally NOT machines you don't have permission to implicate.** This is the part worth being very deliberate about: you are making it _look like_ those IPs attacked the target. If you pick a real organization's IP as a decoy, you are — even if unintentionally — putting their address into someone's IDS/firewall logs as a suspected attacker. For lab/CTF work this matters less if it's all contained infrastructure you control, but it's the one technique in this set with a real "who else does this affect" dimension baked into how it works, not just a legal/ethical footnote.

bash

```bash
nmap -D RND:10 <target>
```

`RND:10` tells nmap to generate 10 random decoy IPs itself. Convenient, but random IPs are often unassigned, in private-use ranges, or belong to arbitrary real hosts on the internet — same consideration applies, just automated rather than chosen by you.

### Where decoy scan gets defeated (your false-negative-style pitfall here)

A few ways decoys can silently fail to protect your identity, even though the scan output looks totally normal to you:

1. **Ingress/egress filtering upstream.** Many networks and ISPs filter packets with spoofed source addresses that don't match the expected topology (this is a real, widely-deployed anti-spoofing practice called **BCP38/ingress filtering**). If the decoy packets never leave your own network because your router/ISP strips or drops spoofed-source packets, the target never even sees the decoys — only your real SYN arrives, and your "crowd" doesn't exist at all. Nmap has no way to detect this from your side; it just sends the packets and assumes they went out as crafted.
2. **Response asymmetry gives you away.** A careful analyst inspecting the target's logs might notice that decoy1, decoy2, decoy3, and decoy4 each show up in the logs _only_ for this exact scan and never appear anywhere else in historical traffic, while your real IP might correlate with other reconnaissance activity elsewhere (DNS lookups, whois queries, other unrelated scans) that the decoys never generated. Attribution evasion isn't perfect anonymity — it raises the analysis cost, it doesn't eliminate the signal for a sufficiently motivated investigator.
3. **Decoys don't help at all against connection-based scans.** Decoy mode only works with scan types that don't require completing a full handshake and getting real data back — **SYN scan (`-sS`) works with decoys.** But **Connect scan (`-sT`)**, or anything requiring your OS to fully establish a session and read a response (like version detection, `-sV`), **cannot use decoys** — because your OS needs the _real_ reply routed back to your actual socket to complete the connection, which breaks the illusion; only you can process replies, so only SYN-style scans that don't need a full round trip are compatible.

### Verifying decoys are actually leaving your network

Same principle as before — check with a packet capture rather than trusting the nmap output alone:

bash

```bash
sudo tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-syn != 0' -w decoy_test.pcap &
nmap -D 10.0.0.5,10.0.0.6,ME,10.0.0.7 -sS <target> -p 80
```

Open `decoy_test.pcap` afterward and confirm you see SYN packets with **different source IPs** (10.0.0.5, 10.0.0.6, your real IP, 10.0.0.7) all going out — if you only see your real IP, your spoofed packets are being stripped somewhere before they even leave your machine/network, and the "decoy scan" you ran provided zero actual protection despite nmap reporting results normally.