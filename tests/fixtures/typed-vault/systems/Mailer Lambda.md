---
type: system
status: shipped
source:
  - acme-notes/services/mailer/handler.py
---
# Mailer Lambda

Consumes the mail queue and calls SES. Runs inside the VPC vpc-0a1b2c3d4e5f60718
behind the security group sg-0123456789abcdef0.
ARN: arn:aws:lambda:us-east-1:111122223333:function:acme-notes-mailer

## Structural
- depends on → [[Mailer Role]]
