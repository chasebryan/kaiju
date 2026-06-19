# Network Model

Kaiju's network reverse-engineering support is evidence-first, with explicit
live TCP actions for authorized targets.

The offline evidence command is:

```bash
kaiju network <evidence-file> [--format text|dot|json]
kaiju network evidence <evidence-file> [--format text|dot|json]
```

The evidence file is plain text from authorized sources such as architecture
notes, firewall exports, DNS notes, connection summaries, proxy logs, or
operator-curated observations. The parser currently recognizes:

- directional observations such as `client -> api.internal:443 tcp`
- URL endpoints such as `https://api.internal.example/v1`
- simple socket pairs such as `tcp 10.0.0.4:51110 10.0.0.8:443 ESTABLISHED`
- single service hints such as `resolver.internal:53 udp`

The output is an inferred map, not ground truth. It includes:

- hosts, classified as IPv4, IPv6, domain, or hostname
- destination services by host, port, and protocol when present
- directed edges between observed source and destination hosts
- line numbers preserving where each fact came from
- ignored-line counts for evidence that did not parse into endpoints

The JSON output uses schema `kaiju.network.v1`. It is deterministic derived
output for headless automation, similar in spirit to the binary project
snapshot.

Classic PCAP imports use the same topology schema:

```bash
kaiju network pcap <pcap-file> [--format text|dot|json]
```

The current PCAP parser handles classic pcap with Ethernet IPv4/IPv6 packets
and extracts TCP, UDP, ICMP, and unknown protocol observations. Packet payloads
are bounded and summarized as byte length, captured preview length, payload
kind, ASCII preview, and hex prefix.

Live TCP probes are explicit:

```bash
kaiju network probe --target HOST:PORT [--timeout-ms N] [--read-bytes N] [--send-text TEXT | --send-hex HEX] [--format text|json]
kaiju network scan --host HOST --ports LIST [--timeout-ms N] [--read-bytes N] [--send-text TEXT | --send-hex HEX] [--format text|json]
```

Probe and scan reports use schema `kaiju.network.probe.v1`. They open TCP
sockets only for the targets supplied on the command line, apply per-target
timeouts, enforce target and byte limits, and summarize any received payload.
There is no ambient discovery, credential capture, exploit step, or privileged
live interface sniffing backend.
