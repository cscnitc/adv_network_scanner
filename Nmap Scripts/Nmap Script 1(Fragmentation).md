We're trying to get **a packet that matches a DENY rule to not be recognized as matching that rule** by the inspection device — even though, functionally, it's still the same request. (Bypass rule)

[[#==**Warning Possibility of False-negative**==]]
[[#HOW FRAGMENTATION WORKS]]
[[#Where fragmentation still has real teeth today]]
[[#Why 3 different Alternatives]]


 # Split packets into 8-byte fragments — makes signature matching harder for basic IDS
 ```bash
 nmap -f -sS -v <target>
 ```


Double fragmentation (16-byte)
```bash
nmap -ff -sS -v <target>
```
# Custom MTU (must be multiple of 8)
```bash
nmap --mtu 24 -sS <target>
```


# ==**Warning: Possibility of False-negative**==

Almost all firewalls/IDS built in the last ~15 years **do fragment reassembly before inspection** specifically because this technique became well known in the late 90s/2000s. So when you run `nmap -f` today:

- If the target's firewall reassembles first → it sees the complete packet just like normal, applies its rules normally, and your result is identical to a non-fragmented scan. The fragmentation added zero evasion value.
- If the scan happens to get through anyway (because the port was just open, or the rule wouldn't have blocked a plain scan either) → someone might conclude "fragmentation evasion worked!" when actually fragmentation was never tested — the result would've been exactly the same with plain `-sS`.



**The only way to know if fragmentation actually did anything** is a controlled comparison:

```bash
# Baseline — no evasion
nmap -sS <target>

# With fragmentation
nmap -f -sS <target>
```

If both give the _same_ result → fragmentation isn't the reason (target reassembles, or nothing was being blocked in the first place). If fragmentation gets through something the baseline didn't → _that's_ a real signal it mattered, and ideally you'd confirm on the defensive side (firewall/IDS logs on the target) that the fragments were logged as separate, unreassembled events rather than caught as one packet.

### Where fragmentation still has real teeth today

- Some embedded/IoT firewalls, older enterprise gear, or misconfigured stateless ACLs still don't reassemble.
- It can still confuse logging/alerting even on devices that _do_ block correctly — the alert might log garbled or incomplete packet info, which matters for the IDS side of your project (detection quality, not just block/allow).
- Combined with small MTU + overlapping fragment tricks (a technique called **fragment overlap attack**, historically used to also confuse reassembly logic itself), it can still trip up specific implementations — this is a deeper rabbit hole (teardrop-style attacks) if you want to go there separately.


# HOW FRAGMENTATION WORKS

**Documentation**
What fragmentation does

IP allows any packet to be split into multiple smaller pieces (fragments) during transmission, to be reassembled at the destination. This is a legitimate, everyday feature of IP — not a hacking trick by itself. Routers do it all the time when a packet is too big for the next network segment's MTU (Maximum Transmission Unit).

`nmap -f` deliberately forces this: instead of sending one clean TCP SYN packet, it chops the packet's headers across multiple tiny IP fragments (8 bytes of data each, by default). Each fragment is a valid IP packet, but a single fragment often doesn't contain the complete TCP header — so a device inspecting fragment-by-fragment cannot see the full picture (like "this is a SYN to port 22") from any one fragment.

Why this used to bypass IDS

Old/naive packet filters operated statelessly and inspected each packet in isolation, without reassembling fragments first. So:

Fragment 1 arrives with part of the IP header + start of TCP header — no complete "SYN to port 22" pattern visible.
Fragment 2 arrives with the rest — but this filter isn't tracking "fragment 1 + fragment 2 = one packet," so it inspects fragment 2 alone too.
Neither fragment alone matches the signature rule, so the filter passes both through.
The destination host's IP stack reassembles them back into the original packet and processes it normally.

So the scan succeeds — not because you broke encryption or found a hole, but because the inspection point never saw the "whole picture" to match against its rules, even though the actual final packet was completely ordinary.


# Why 3 different Alternatives

### 1. Some devices flag or drop suspiciously tiny fragments

8-byte fragments are _unusually_ small — normal network traffic almost never fragments this aggressively (real-world fragmentation from actual MTU limits usually produces fragments in the hundreds of bytes). Some firewalls/IDS have specifically been hardened to notice "hey, these are all suspiciously tiny 8-byte fragments" and either:

- Flag it as an evasion attempt itself (ironically, the attempt to evade becomes the signature that gets you caught)
- Have a minimum fragment size policy and just drop anything smaller than some threshold as malformed/suspicious

So `-ff` (16-byte) exists partly to be a _less conspicuous_ fragment size — still small enough to split the header, but not screaming "this is an evasion tool" as loudly as the extreme 8-byte default.

### 2. 8 bytes might not even successfully split what you need to split

Depending on exact header layout and where fields land, 16-byte fragments split the header at a _different_ boundary point than 8-byte fragments do. If a particular firewall's inspection logic has a quirk — say, it actually does look at the first 12 bytes of any fragment regardless of size — then 8-byte fragments might still leak enough info to match a rule, while a different split point wouldn't. You're testing different "cut points" against however that specific device's inspection logic works, since you don't know it in advance.

### 3. `--mtu` gives you far more control and larger scale testing

`-f`/`-ff` are just shortcuts for `--mtu 8` / `--mtu 16`. The `--mtu` flag lets you pick _any_ multiple of 8 — so you're not limited to just two presets:

bash

```bash
nmap --mtu 24 -sS <target>
nmap --mtu 32 -sS <target>
nmap --mtu 1200 -sS <target>   # barely fragments at all — mimics normal MTU-driven fragmentation
```

That last one is actually important: real MTU-caused fragmentation on the internet typically happens around 1500 bytes (standard Ethernet MTU) minus overhead — so fragments in the 1200-1400 range **look like ordinary network behavior**, not an attack. If your goal is to blend in rather than obviously evade, a large-but-still-fragmented MTU can slip past "this traffic looks like an evasion tool" heuristics while still occasionally splitting a header if the original packet is small enough.

### Practical takeaway for your testing

Think of these not as "3 fixed strengths of the same button" but as **a size dial** trading off two competing goals:

- **Smaller fragments** → more reliably split the header apart (better chance of defeating inspection) → but more conspicuous, more likely to be dropped/flagged by fragment-size-aware defenses, and some very old network gear can't even handle 8-byte fragments reliably
- **Larger fragments** → look more like normal traffic, less likely to be flagged as an evasion attempt → but less likely to actually land a clean split across the TCP header fields you need separated

So in a real test matrix for your scanner project, you'd probably want to sweep across a few MTU values (8, 16, 24, and maybe a "large/stealthy" one like 1200) against each target and log which ones actually flip filtered→open, rather than assuming the default `-f` is universally optimal. Different firewalls will have different sweet spots.