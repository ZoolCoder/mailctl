---
description: Show what mailctl would change for one or all domains, explained in plain words
argument-hint: [domain ...]
---

Call `mail_plan` (or `mailctl plan -json`) for the given domains, all domains when none are given. Explain every action grouped by resource, and call out MX changes, DMARC policy changes, deletions and manual steps. Do not apply. For a plan with more than a few actions or any risky change, spawn the `deliverability-reviewer` agent and include its verdict.

Arguments: $ARGUMENTS
