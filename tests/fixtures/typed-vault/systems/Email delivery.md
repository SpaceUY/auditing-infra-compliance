---
type: system
status: shipped
source:
  - acme-notes/services/mailer/README.md
---
# Email delivery

Acme Notes sends transactional email (invitations, password resets) to users through
SES. The mailer consumes a queue and sends from the verified domain acme-notes.example.

## Structural
- depends on → [[SES Identity]]
- depends on → [[Mailer Lambda]]
- depends on → [[Mail Queue]]
- depends on → [[DMARC reject policy]] because the domain still has p=none
- requires → [[PII handling]]
