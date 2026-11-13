---
type: system
status: shipped
source:
  - acme-notes/infra/sqs.tf
---
# Mail Queue

SQS queue that buffers outbound mail. Messages carry the recipient email address.
ARN: arn:aws:sqs:us-east-1:111122223333:acme-notes-mail-queue

## Structural
