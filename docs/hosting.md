# Hosting

This server is built to be hosted as **one private instance per person**: each person gets their own container, their own disk, their own address and their own sign-in. Instances share nothing.

> Linking WhatsApp this way uses an unofficial linked device. That is against WhatsApp's Terms of Service and can get an account restricted or banned. Everyone who links an account should know that first.

## What you need

- A container host with a persistent disk and HTTPS. A Render Blueprint is included (`render.yaml`); any host that runs a Dockerfile works.
- One service per person.
- For each person: their WhatsApp on a phone, to scan a QR code once.

## On Render

1. Fork or push this repository to your own Git host and connect it to Render.
2. In `render.yaml`, rename the example service (`wa-yourname`) and its disk. To add more people, copy the whole service block once per person and give each a unique `name` and disk `name`.
3. Create a Blueprint from the repository in the Render dashboard and apply it.
4. When a service is live, open its **Environment** page and copy the generated `SETUP_TOKEN`. Give that code and the service address to the person it is for, and to nobody else.

The Blueprint was checked with `render blueprints validate`. It has not been deployed by the authors of this fork, so treat the first deploy as a test.

## What each person does

1. Open `https://<their-service>/setup`, enter the setup code, and choose a passphrase of at least 12 characters.
2. Save the recovery code shown next. It is displayed once. Without the passphrase or the recovery code the archive cannot be opened by anyone.
3. Follow the link to the pairing page and scan the QR code from WhatsApp (Settings → Linked Devices → Link a Device). Keep the phone online for a few minutes while history arrives.
4. In Claude, add `https://<their-service>/mcp` as a custom connector. Claude sends them to a page on their instance, where they enter the passphrase and tick what Claude may do: read (always), send messages, manage groups and settings.

To link or re-link WhatsApp later, open `/setup` and sign in with the passphrase.

## The owner page

Signing in at `/setup` (with the passphrase or the recovery code) opens a page where the owner can:

- **Link or re-link WhatsApp.**
- **Change the passphrase.** Apps that are already connected stay connected.
- **Sign all apps out.** Deletes every sign-in; each app has to be approved again. Use it if a device is lost.
- **Lock now.** Disconnects from WhatsApp and discards the key from memory until the next sign-in.

If the passphrase is forgotten, "Forgot your passphrase?" on the sign-in page takes the recovery code and sets a new passphrase. The archive and connected apps are kept. If both the passphrase and the recovery code are lost, the archive cannot be opened by anyone: delete the disk and set the instance up again.

## Settings

| Variable | Meaning | Default |
|---|---|---|
| `WHATSAPP_MCP_ADDR` | Address to listen on, for example `0.0.0.0:10000` | `127.0.0.1:8765` |
| `WHATSAPP_MCP_ALLOW_REMOTE` | Must be `1` to listen beyond the machine itself | off |
| `PUBLIC_URL` | The https address clients use. On Render, `RENDER_EXTERNAL_URL` is used when this is unset | none |
| `SETUP_TOKEN` | One-time code for `/setup`. Empty means nobody can set the instance up | none |
| `IDLE_LOCK` | How long the instance stays unlocked without use, as a duration (`15m`, `90s`) | `15m` |
| `ALLOW_NEW_RECIPIENTS` | Allow sending to chats that have no history | `false` |
| `SEND_CONFIRM` | `new_recipients`, `always` or `off`: which sends are held as a draft until confirmed | `new_recipients` |
| `OAUTH_REDIRECT_ALLOWLIST` | Extra exact https sign-in callbacks, comma-separated. Claude's are built in | none |
| `WHATSAPP_MCP_READ_ONLY` | `1` removes every tool that sends or changes anything, whatever a sign-in was granted | off |

Do **not** set `WHATSAPP_MCP_VAULT_KEY` on a hosted instance. That variable selects a local development mode that keeps the data key in the environment, and the server refuses to combine it with remote connections.

## What is stored, and who can read it

- **On disk:** two SQLCipher-encrypted databases (the message archive and the WhatsApp login keys) and one small unencrypted state database, `meta.db`. `meta.db` holds sealed copies of the key and one-way IDs of sign-in tokens. Nothing in it opens anything on its own.
- **The key** is created at setup and never written in usable form. It exists in memory only between a request that carries a valid token (or the owner's passphrase) and the idle lock.
- **Media** is decrypted in memory when asked for and never written to disk. Uploads waiting to be sent and large downloads waiting to be collected are held in memory for at most ten minutes and work once.
- **While locked**, the instance has no key, no open database and no connection to WhatsApp. Messages that arrive meanwhile wait on WhatsApp's servers and are collected at the next unlock. An instance that is not used for 30 days is dropped by WhatsApp and has to be linked again; the archive is kept.

What this does not protect against:

- **Whoever controls the hosting account** can deploy a changed image, or open a shell while an instance is unlocked. If someone needs protection from the host, they should run their instance under their own hosting account.
- **The LLM provider** sees everything the tools return.
- **Anyone who can reach the sign-in page** can submit wrong passphrases and pause passphrase sign-in for up to 15 minutes at a time. Connected apps keep working, and the recovery code is never paused, so the owner can still sign in and approve apps with it.

## Send safety

- A sign-in that was only granted reading is not offered any tool that sends or changes anything.
- Sending to a chat with no history is refused unless `ALLOW_NEW_RECIPIENTS=true`. With it on, such sends are held as a draft and need a second, explicit `confirm_send` (`SEND_CONFIRM=new_recipients`); `SEND_CONFIRM=always` holds every send.
- Sends are rate limited on the server (at least 45 seconds apart, 30 an hour; stricter to people who have never written to you). Locking and unlocking does not reset the limit.
- Message text handed to the model is labelled as written by other people and not to be followed as instructions. The confirm step guards against mistakes; it is not a barrier against a hijacked model, which is what the permissions, the new-recipient block and the rate limit are for.

## Attachments

- **Sending a file:** by a public https link, by a one-time upload page (`create_upload_link`, for a file on the person's own device), or inline for files up to 5 MB. Links to private or local addresses are refused. Files of up to 64 MB can be sent.
- **Receiving media:** images and voice notes come back inline; documents and videos up to 5 MB come back as an attachment in the result; anything larger, up to 64 MB, comes back as a one-time download link that expires after ten minutes. The link always downloads the file; it never opens it in the browser.
- At most two media files are fetched at once, and at most 128 MB of uploads and downloads is held in memory at a time.
- Messages can only be sent to people and groups, never to broadcast addresses (such as status) or channels.

## Other hosts

Anything that runs the Dockerfile with a persistent volume at `/home/app/store` and terminates HTTPS in front of it will do. Set `WHATSAPP_MCP_ADDR`, `WHATSAPP_MCP_ALLOW_REMOTE=1`, `PUBLIC_URL` and `SETUP_TOKEN`. The container starts as root only to take ownership of the mounted volume, then drops to an unprivileged user before the server starts.

## Updating

WhatsApp changes its protocol regularly and stale clients stop connecting. The CI workflow probes for a newer `whatsmeow` every week. Deploys are manual in the Blueprint (`autoDeployTrigger: "off"`) so an update can be tried on one instance before the rest.
