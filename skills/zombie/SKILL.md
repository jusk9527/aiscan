---
name: zombie
description: Use this skill when working with zombie for authorized weak credential checks and authentication result analysis.
internal: true
---

# Zombie

Zombie is the weak credential checking tool in aiscan.

Capabilities:

- test supported network services for weak credentials when authorized
- report service URI, protocol, host, port, module, username, password, and authentication result
- distinguish successful credentials, failed attempts, connection errors, lockouts, and unsupported services
- expose retry, timeout, and module-specific messages

Common usage:

```bash
zombie -i <service-url> --top 3
zombie -i ssh://user@127.0.0.1:22 -p <password>
zombie -l <service-url-file> --top 10
```

Notes:

- `-i` is zombie service input.
- `-p` is zombie password, not aiscan prompt.
- User intent decides whether the credential output should be summarized, assessed, correlated, or explained.
