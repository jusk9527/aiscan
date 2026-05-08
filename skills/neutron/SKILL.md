---
name: neutron
description: Use this skill when working with neutron for template-based POC execution, template filtering, and POC result analysis.
internal: true
---

# Neutron

Neutron is the template-based POC execution tool in aiscan.

Capabilities:

- run embedded or custom POC templates against URL, host, or ip:port targets
- filter templates by id, tag, severity, fingerprint, or template path
- report target, template id, template name, severity, tags, related fingerprints, match state, extracts, errors, and summary data
- list selected templates without executing them

Common usage:

```bash
neutron -u <url> -s critical,high
neutron -u <url> --finger <finger-name>
neutron -u <url> --id <template-id>
neutron -l <target-file> --tags cve,rce -c 10
neutron -u <url> --template-list
```

Notes:

- Severity is template metadata.
- A match is scanner evidence; user intent decides whether to summarize, triage, verify, correlate, or report it.
