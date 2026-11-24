# Vault repository audit

Reviewed 24 November 2026 against baseline `9152ab3`. The review followed data from setup and OAuth through the MCP gateway, WhatsApp client, encrypted stores, media handling and release image. Verification uses synthetic account fixtures.

| Priority | Finding | Remediation and evidence |
| --- | --- | --- |
| High | Git could stage the untracked local vault key. Installation and container publishing pointed to upstream. | Ignore the private directory and use the fork for installation and image publishing. Verify with `git check-ignore .local/vault.key`. |
| High | Owner sessions held a usable key independently of the configured idle lock. | Store a one-way cookie ID and a key sealed under the browser cookie. Gateway tests cover configured expiry, recovery and explicit lock. |
| High | Two assistants with matching permissions shared a draft store. The owner could only revoke all apps together. | Key pending sends and uploads by the issuing grant family. Validate browser links against the active family. Owner controls and two-client tests exercise independent revocation. |
| High | The hosted status tool exposed the device pairing QR to read grants. | Keep the QR on the owner pairing page. The hosted status tests cover every permission tier. |
| Medium | Message IDs can repeat across chats. A context lookup could return a different chat’s conversation. | Resolve the composite message key and request the chat when an ID is ambiguous. Research links identify one archived row across restarts. |
| Medium | Attachment confirmation could resolve a different file when a link changed. | Stage the bytes when drafting. A regression test changes the remote file before confirmation and checks the bytes handed to the sender. |
| Medium | Archive opening rewrote timestamps and updated the full-text index on every unlock. | Commit legacy migrations and their version marker in one transaction. A regression fixture rejects a repeated rewrite and verifies rollback. |
| Medium | Expired files could stay resident until another transfer or lock. | Run expiry independently of requests in both modes and test memory accounting on a quiet instance. |
| Medium | The MCP SDK contained a client transport advisory. The baseline Go scan found zero affected symbols called by this server. | Upgrade to v1.6.0 and run the protocol tests. [Go vulnerability report](https://pkg.go.dev/vuln/GO-2026-6911) |
| Medium | Debian classified 23 open mbedTLS records in the Bookworm runtime as end-of-life. | Move the runtime to a digest-pinned Debian 13 image. The rebuilt image passed offline voice encoding and reopened an encrypted volume created by the previous image. [Debian mbedTLS tracker](https://security-tracker.debian.org/tracker/source-package/mbedtls) |
| Medium | Native voice-note conversion accepted the decoder’s protocol defaults and collected its entire diagnostic stream in memory. | Restrict input protocols to pipes, cap retained diagnostics at 4 KiB and enforce a five-minute conversion deadline. Test the packaged encoder with synthetic audio and networking disabled. |
| Medium | Standard CI skipped binary OAuth tests and Linux image boot. | Run binary end-to-end tests and boot the Dockerfile with an ephemeral encrypted volume and networking disabled. |

## Verification

The binary end-to-end tests use disposable vaults and two independent OAuth clients. They cover discovery, separate consent, refresh and revocation, concurrent archive reads, private citation pages, idle locking and process restart. Unit and race tests cover published client metadata, archive migrations, scope filtering, confirmation and transfers. CI also builds and boots the Linux image. The connector product interfaces and delivery to a paired phone require a separate hosted acceptance test.

Two additional local checks used the providers’ live public client documents for consent, PKCE and tool discovery, then exercised the Linux container with a public Host header and HTTPS issuer. The account fixtures stayed on loopback in both checks.

The Go source scan with `govulncheck v1.10.0` reported zero vulnerabilities. For the local Linux/arm64 image, we also compared all 203 installed Debian source packages with the Debian 13 tracker on 24 November 2026. The image included FFmpeg `7:7.1.5-0+deb13u1` and mbedTLS `3.6.6-0.1~deb13u1`. The tracker listed no released fixes newer than the installed versions. It still listed 466 open source-package records across those packages, including 366 awaiting urgency assignment. Assessing their effect on this binary requires checking which native code paths it uses. [Debian tracker data](https://security-tracker.debian.org/tracker/data/json)

## Coverage and residual risks

- **Vault and recovery.** SQLCipher protects the archive and linked-device database. The separate metadata database stores credential-derived identifiers and sealed keys. Wrong-key, recovery, rotation and lock tests exercise these boundaries. A privileged host can inspect an unlocked process.
- **History and media.** Tests cover FTS updates, edits, revocation, pagination, poll replay, phone/LID mappings, media retry integrity and one-time transfers. Remote transcription sends selected audio to the explicitly configured service.
- **Native dependencies.** The Go driver embeds SQLCipher 4.4.2 and SQLite 3.33.0. Go symbol scanning covers Go code only. A replacement needs compatibility tests for encrypted files, FTS4 and whatsmeow migrations. The image pins its base digests, installs Debian updates at build time and drops privileges before serving.
- **Operations.** Hosted readiness indicates a running gateway. The authenticated status tool reports the device connection. Global passphrase backoff can affect multiple browsers. The recovery code remains available during a pause. Live connector acceptance requires an HTTPS instance and the owner's phone.

