# 0004. Attachments are stored in MySQL

## Context

The reference architecture (BoK 2.3) puts attachments in a MinIO object store in the data zone. In late
2025 MinIO stopped publishing images and binaries for its community edition. A prototype pinned to the
last published image would ship with known, unpatched vulnerabilities, which SC-08 and CRA Annex I
forbid. Building MinIO from source was out of scope for the prototype.

## Decision

Attachment bytes are stored in their own MySQL table, `attachment_content` (`LONGBLOB`), keyed by the
attachment's UUID. Metadata lives in `attachment`. All access goes through `AttachmentService`, which:

- resolves the attachment through its parent ticket and `TicketAccessService` (SC-03);
- inspects the bytes before storing them (SC-05);
- serves them only as a download with `nosniff`, `Content-Disposition: attachment` and a sandboxing CSP.

Two limits keep the table within what MySQL handles comfortably: 10 MB per file and ten files per
ticket.

## Consequences

- SC-05 is kept in full: the store is outside any web root, names are random (the UUID), and retrieval
  goes only through the API. The data-at-rest protection (SC-06) of the MySQL volume now covers
  attachments too.
- Backups grow with the attachments, and there is one store fewer to back up and secure.
- Moving to an S3-compatible store later changes `AttachmentService` and nothing else. The entity is
  already separate, so listing attachments never loads their bytes.
