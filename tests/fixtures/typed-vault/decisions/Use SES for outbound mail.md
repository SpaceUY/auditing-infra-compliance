---
type: decision
status: shipped
source:
  - acme-notes/docs/adr/0003-ses.md
---
# Use SES for outbound mail

Outbound mail goes through SES instead of a self-hosted relay.

## Structural
- establishes → [[PII handling]]
