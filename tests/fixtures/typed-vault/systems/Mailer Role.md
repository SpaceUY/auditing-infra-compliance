---
type: system
status: shipped
source:
  - acme-notes/infra/iam.tf
---
# Mailer Role

Execution role of the mailer, limited to ses:SendEmail and the queue.
ARN: arn:aws:iam::111122223333:role/acme-notes-mailer-role

## Structural
