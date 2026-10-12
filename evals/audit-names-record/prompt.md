---
max_turns: 8
allowed_tools: [Read, Glob, Grep, Skill]
tags: [audit, deliverability, core]
description: An audit failure is explained in plain words with the exact record or config line that fixes it.
---

My mail from example.com keeps landing in spam. Audit says:

```json
[
  {
    "domain": "example.com",
    "ok": false,
    "checks": [
      {"name": "mx", "want": "mailserver.purelymail.com", "got": "mailserver.purelymail.com", "ok": true},
      {"name": "spf", "want": "v=spf1 include:_spf.purelymail.com ~all", "got": "v=spf1 include:_spf.purelymail.com ~all", "ok": true},
      {"name": "dkim", "want": "3 CNAME records", "got": "3 CNAME records", "ok": true},
      {"name": "dmarc", "want": "v=DMARC1; p=none; rua=mailto:dmarc@example.com", "got": "", "ok": false}
    ],
    "notes": []
  }
]
```
