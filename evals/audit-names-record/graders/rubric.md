---
type: llm
weight: 2
---

The only failing check is DMARC: no record exists.

PASS if the reply says in plain words that receivers have no DMARC policy for the domain, names the fix exactly (a TXT record at `_dmarc.example.com` with `v=DMARC1; p=none; rua=mailto:dmarc@example.com`, preferably produced by the config's `deliverability.dmarc` block followed by plan and apply after a yes), and recommends staging: `p=none` first, then `quarantine`, then `reject`.
FAIL if it blames SPF, DKIM or MX, jumps straight to `p=reject`, or applies without a plan.
