# Vault repository audit

Reviewed 24 November 2026 against baseline `9152ab3`. The review followed data from setup and OAuth through the MCP gateway, WhatsApp client, encrypted stores, media handling and release image. Verification uses synthetic account fixtures.

| Priority | Finding | Remediation and evidence |
| --- | --- | --- |
| High | Git could stage the untracked local vault key. Installation and container publishing pointed to upstream. | Ignore the private directory and use the fork for installation and image publishing. Verify with `git check-ignore .local/vault.key`. |
| High | Owner sessions held a usable key independently of the configured idle lock. | Store a one-way cookie ID and a key sealed under the browser cookie. Gateway tests cover configured expiry, recovery and explicit lock. |
| High | Two assistants with matching permissions shared a draft store. The owner could only revoke all apps together. | Covered in the connector access changes and two-client acceptance tests. |
| Medium | Archive opening rewrote timestamps and updated the full-text index on every unlock. | Commit legacy migrations and their version marker in one transaction. A regression fixture rejects a repeated rewrite and verifies rollback. |
| Medium | Expired files could stay resident until another transfer or lock. | Run expiry independently of requests in both modes and test memory accounting on a quiet instance. |
| Medium | The MCP SDK contained a client transport advisory. The baseline Go scan found zero affected symbols called by this server. | Upgrade to v1.6.0 and run the protocol tests. [Go vulnerability report](https://pkg.go.dev/vuln/GO-2026-6911) |
| Medium | Standard CI skipped binary OAuth tests and Linux image boot. | Run binary end-to-end tests and boot the Dockerfile with an ephemeral encrypted volume and networking disabled. |

## Coverage and residual risks

- **Vault and recovery.** SQLCipher protects the archive and linked-device database. The separate metadata database stores credential-derived identifiers and sealed keys. Wrong-key, recovery, rotation and lock tests exercise these boundaries. A privileged host can inspect an unlocked process.
- **History and media.** Tests cover FTS updates, edits, revocation, pagination, poll replay, phone/LID mappings, media retry integrity and one-time transfers. Remote transcription sends selected audio to the explicitly configured service.
- **Native dependencies.** The Go driver embeds SQLCipher 4.4.2 and SQLite 3.33.0. Go symbol scanning covers Go code only. A replacement needs compatibility tests for encrypted files, FTS4 and whatsmeow migrations. The image pins its base digests, installs Debian updates at build time and drops privileges before serving.
- **Operations.** Hosted readiness indicates a running gateway. The authenticated status tool reports the device connection. Global passphrase backoff can affect multiple browsers. The recovery code remains available during a pause. Live connector acceptance requires an HTTPS instance and the owner's phone.

