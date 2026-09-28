Find a good zombie first (idle host, sequential IP ID)
```bash
nmap -sI <zombie_ip> <target>
```


Verify zombie candidacy
```bash
nmap -O <zombie_ip>   # look for "IP ID Sequence Generation: Incremental"
```

# Practical workflow
```bash
# Step 1: check candidacy
nmap -O 192.168.1.50

# Step 2: if "Incremental" — verify it's currently quiet (low traffic makes it a better zombie)
# no formal nmap flag for this — you'd manually probe a few times and watch how much
# the IP ID jumps between probes when you're NOT scanning anything through it:
nmap -sI 192.168.1.50 192.168.1.50 --top-ports 1   # sanity check, minimal probe

# Step 3: run the actual idle scan
nmap -sI 192.168.1.50 -Pn <target>
```

`-Pn` is worth noting here too — it skips nmap's normal host discovery ping, which is often desired in idle scans since you generally don't want extra probes muddying the picture.
### What nmap normally does before scanning

By default, before nmap even starts port-scanning a target, it runs a **host discovery** step — basically "is this target even alive/reachable?" It does this by sending some combination of probes (ICMP echo request, a TCP SYN to port 443, a TCP ACK, sometimes an ICMP timestamp request depending on privileges) and waiting for _any_ response.

If nothing responds to these discovery probes, nmap assumes the host is down and **skips scanning it entirely** — even if the host is actually up but just configured to not respond to pings (very common — lots of firewalls block ICMP by default as basic hygiene).

`-Pn` means: **"treat the target as up, skip discovery, go straight to the actual scan you asked for."** The `P` is for "ping," and `n` means "no" — no ping/discovery phase.

### Why this matters normally (even outside idle scan)

If you're testing a target you already know is alive (you're doing an authorized pentest, or it's your own lab machine), and it happens to block ICMP/ping-type probes, nmap might wrongly conclude "host is down" and refuse to scan it at all — giving you a false "0 hosts up" result even though it's very much up and listening on plenty of ports. `-Pn` sidesteps that.

### Why it specifically matters for idle scan

This is the more important reason here. Think about what host discovery would actually do in an idle scan context:

- Host discovery probes go out **from your own real IP** to the target — that's the whole point of nmap "checking if it's alive" first.
- But the entire premise of idle scan is that **your IP never touches the target directly** — that's the stealth/spoofing property we spent this whole conversation building up.

So if you let nmap run its normal discovery phase before the idle scan, you'd send a giveaway packet from your real IP straight to the target — completely undermining the reason you're doing an idle scan in the first place. `-Pn` isn't just a minor optimization here; it's **necessary** to preserve the actual security property (source concealment) that idle scan exists to provide.


[[#The three-step trick, one port at a time]] --How this scan works
### ==False-negative risk== 

This one has more failure points than fragmentation, and unlike fragmentation (where "it didn't work" is fairly obvious), idle scan can produce **confident, clean-looking, completely wrong answers**:

1. **The zombie must actually be idle.** If any other traffic on the internet causes the zombie to send packets during your test window — a normal user browsing, another scan hitting it, an OS keepalive — its IP ID increments for reasons that have nothing to do with your target. You'll misread noise as signal.
2. **The zombie must use a predictable, incrementing IP ID.** Modern OSes (recent Windows, Linux, macOS) largely use **randomized IP IDs** specifically to kill this technique. If you pick a modern, patched host as your zombie, idle scan simply won't work — not "won't work well," won't work _at all_, and nmap may still print output that looks like a result.
3. **Network jitter/loss between you-zombie and zombie-target** can cause timing misreads even with a good zombie.

Nmap actually tries to protect you from failure mode #2 — before scanning, it checks the zombie's IP ID behavior and will explicitly warn you if the host isn't a good idle-scan candidate, rather than silently giving you garbage results.

### The core idea: using a third machine as your alibi

Idle scan lets you scan a target **without ever sending a single packet from your own IP to the target directly**. Instead, you find some other host on the internet (the "zombie") that's idle, and you trick it into unknowingly scanning the target for you. The target's logs only ever see the zombie's IP — yours never appears.

### The side-channel it exploits: IP ID

Every IP packet has an **Identification (IP ID)** field in its header — normally used to reassemble fragments . On many systems, this field isn't random — it's a simple **global counter that increments by 1 every time the host sends any packet**, to anyone, for any reason.

So if a host's IP ID sequence looks like: `41000, 41001, 41002, 41003...` — that's a predictable, incrementing counter. This predictability is exactly what idle scan hijacks.

### The three-step trick, one port at a time

**Step 1 — Probe the zombie to learn its current IP ID**

```
You → Zombie: SYN-ACK (unsolicited)
Zombie → You: RST, with IP ID = 41000
```

Zombie gets a SYN-ACK it never asked for, replies with RST as any normal TCP stack does, and that RST packet's IP ID tells you the counter's current value: 41000.

**Step 2 — Spoof a SYN from the zombie's IP to the target**

```
You (pretending to be Zombie) → Target: SYN, dest port 22
```

You forge the source IP to say it's the Zombie, not you, and send this to the target. The target thinks the Zombie is trying to connect.

**Step 3 — What happens next depends on whether the port is open**

_If the target's port is OPEN:_

```
Target → Zombie: SYN-ACK   (target thinks zombie asked to connect)
Zombie → Target: RST       (zombie has no memory of asking — sends RST to reset)
```

This RST from the zombie is a real packet the zombie sends, which means the zombie's IP ID counter increments by 1.

_If the target's port is CLOSED:_

```
Target → Zombie: RST       (port refuses, tells zombie directly)
Zombie: does nothing        (RST doesn't need a reply)
```

No packet sent by the zombie, so its counter does **not** increment.

**Step 4 — Probe the zombie again, check the IP ID**

```
You → Zombie: SYN-ACK (unsolicited, again)
Zombie → You: RST, with IP ID = ?
```

- If IP ID is now **41002** (jumped by 2) → the zombie sent one extra packet in between (its RST to the target) → port is **OPEN**.
- If IP ID is now **41001** (jumped by only 1, from your own step-1 probe interaction... wait — actually from this step's own probe) → zombie sent nothing extra → port is **CLOSED/FILTERED**.

### Why this method?

You never sent a single packet _from your own IP_ to the target. The only packets touching the target had the zombie's IP as source. If the target logs "who tried to connect," it logs the zombie — completely innocent, uninvolved, unaware. You learned the port state purely by **watching a side-effect** (a counter incrementing) on a totally uninvolved third machine.