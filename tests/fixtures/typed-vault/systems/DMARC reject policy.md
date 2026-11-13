---
type: system
status: proposed
source:
  - acme-notes/docs/email-hardening.md
---
# DMARC reject policy

Proposal to move the DMARC record of acme-notes.example from p=none to p=reject.
The domain publishes p=none today (see Email delivery); the p=reject record is not published yet.

## Structural
- prevents → [[Spoofed sender domain]]
