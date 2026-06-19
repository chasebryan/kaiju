# Network Model

Kaiju's network reverse-engineering support is offline and evidence-driven. It
does not scan, probe, capture packets, intercept traffic, or open sockets.

The first command is:

```bash
kaiju network <evidence-file> [--format text|dot|json]
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
snapshot. Future work can add structured imports for specific log formats, but
new importers should preserve source line or record provenance and keep network
collection outside Kaiju unless a separate capability model is designed first.
