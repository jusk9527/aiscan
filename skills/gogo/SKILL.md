---
name: gogo
description: Use this skill when working with gogo for host, port, service, banner, fingerprint, or vulnerability-hint discovery.
internal: true
---

# Gogo

Gogo is the host and service discovery tool in aiscan.

Capabilities:

- discover live hosts and open ports from IP, CIDR, host, or target files
- identify protocols, services, banners, TLS hints, and response metadata
- match service and web fingerprints from the embedded finger engine
- surface focus fingerprints and vuln hints as leads for later analysis
- produce scan summary data such as alive count, total count, timing, and errors

Common usage:

```bash
gogo -i <ip-or-cidr> -p top100
gogo -i <ip-or-cidr> -p 80,443,8080
gogo -i <target-file> -p all
```

Notes:

- `-i` is gogo input, not aiscan agent input.
- `-p` is gogo ports, not aiscan prompt.
- Fingerprints and vuln hints are evidence leads; user intent decides whether to summarize, analyze, verify, compare, or plan follow-up work.
