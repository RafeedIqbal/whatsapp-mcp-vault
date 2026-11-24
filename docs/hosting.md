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

## Connect ChatGPT and Claude to one account

If your current archive uses `WHATSAPP_MCP_VAULT_KEY`, keep that directory and key together. Create the hosted vault on a separate empty volume and link it once. Importing a key-in-environment archive into a passphrase vault is still unsupported.

1. Open the instance’s HTTPS `/setup` page with its one-time setup code. Choose a passphrase, save the recovery code, and use WhatsApp’s **Linked devices** screen to scan the owner pairing page once.
2. Open **Connected apps** at `/setup` and copy the full URL ending in `/mcp`.
3. In ChatGPT on the web, open **Plugins**, select **Add custom MCP server** and enter that URL. Choose **OAuth** and the published client identity (CIMD). Install the resulting private plugin. Workspace permissions govern who can add an MCP server. [OpenAI custom MCP guide](https://developers.openai.com/api/docs/guides/custom-mcp-server)
4. In Claude, open **Customize → Connectors → Add custom connector**. Enter the same URL, choose **Sign in now** and **Use Claude’s published identity**. Both clients can also use automatic dynamic registration. [Claude connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
5. Approve each connection with the vault passphrase. Reading is included. Tick sending or account management for each app individually. Call `get_status` and `list_chats` from both to check the shared account and archive.

The server validates the published client document at an exact HTTPS address, PKCE S256, the callback, the issuer and the MCP resource. ChatGPT normally returns to `https://chatgpt.com/connector_platform_oauth_redirect`. If the ChatGPT management screen shows a connection-specific callback, add its exact HTTPS URL to `OAUTH_REDIRECT_ALLOWLIST` and choose dynamic registration. [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth)

## Search and cite messages

Ask either assistant to “find the WhatsApp messages about the workshop and cite them”. With read permission, `search` returns the 20 most recent matches and `fetch` opens a selected message. Both operate on the encrypted cache, including while the phone is offline. Full-text queries match word prefixes in any order. Emoji and scripts without word boundaries use literal matching. [OpenAI research tool format](https://developers.openai.com/api/docs/mcp)

Each result links to `/sources/<opaque-id>` on this instance. The link takes you through owner sign-in and back to the message. Both assistants get the same link across restarts. If WhatsApp reports an edit or deletion for everyone, the result reflects that status. The archive retains the last cached text of deleted messages and marks it with the deletion time.

## The owner page

Open `/setup` to see the app names and their granted permissions. **Disconnect** ends one authorisation, including its refresh tokens and pending transfers. **Sign all apps out** ends every connection. To change a grant, disconnect it and approve it again with the desired permissions. **Lock now** closes the WhatsApp runtime and clears pending work. An authorised app can reopen it on its next request.

Use the recovery code on the sign-in page to set a new passphrase. The archive and connected apps survive a passphrase change.

## Settings

| Variable | Meaning | Default |
|---|---|---|
| `WHATSAPP_MCP_ADDR` | Address to listen on, for example `0.0.0.0:10000` | `127.0.0.1:8765` |
| `WHATSAPP_MCP_ALLOW_REMOTE` | Must be `1` to listen beyond the machine itself | off |
| `PUBLIC_URL` | The https address clients use. On Render, `RENDER_EXTERNAL_URL` is used when this is unset | none |
| `SETUP_TOKEN` | One-time code for `/setup`. Empty means nobody can set the instance up | none |
| `IDLE_LOCK` | How long the instance stays unlocked without use, as a duration (`15m`, `90s`) | `15m` |
| `ALLOW_NEW_RECIPIENTS` | Allow sending to chats that have no history | `false` |
| `SEND_CONFIRM` | `new_recipients`, `always` or `off`: which sends are held as a draft until confirmed | `always` for hosted instances |
| `OAUTH_REDIRECT_ALLOWLIST` | Extra exact https sign-in callbacks, comma-separated. ChatGPT and Claude callbacks are built in | none |
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
- Sending to a chat with no history is refused unless `ALLOW_NEW_RECIPIENTS=true`. Hosted instances default to `SEND_CONFIRM=always`. The assistant displays the recipient and content, asks for approval and uses `confirm_send` on the same connection. This includes replies, files, polls, votes, reactions and group additions that may send private invitations. Manage-only connections can add participants and report invitations as required.
- Sends are rate limited on the server (at least 45 seconds apart, 30 an hour; stricter to people who have never written to you). Locking and unlocking does not reset the limit.
- Message text handed to the model is labelled as written by other people and not to be followed as instructions. The confirm step guards against mistakes; it is not a barrier against a hijacked model, which is what the permissions, the new-recipient block and the rate limit are for.

## Attachments

- **Sending a file:** by a public https link, by a one-time upload page (`create_upload_link`, for a file on the person's own device), or inline for files up to 5 MB. Links to private or local addresses are refused. Files of up to 64 MB can be sent.
- **Receiving media:** images and voice notes come back inline; documents and videos up to 5 MB come back as an attachment in the result; anything larger, up to 64 MB, comes back as a one-time download link that expires after ten minutes. The link always downloads the file; it never opens it in the browser.
- Voice-note conversion accepts the uploaded stream over a pipe. Conversion stops after five minutes or when the caller cancels. If a clip needs a format the streaming converter cannot read, send it as an audio attachment with `send_file`.
- At most two media files are fetched at once, and at most 128 MB of uploads and downloads is held in memory at a time.
- Messages can only be sent to people and groups, never to broadcast addresses (such as status) or channels.

## Other hosts

Anything that runs the Dockerfile with a persistent volume at `/home/app/store` and terminates HTTPS in front of it will do. Set `WHATSAPP_MCP_ADDR`, `WHATSAPP_MCP_ALLOW_REMOTE=1`, `PUBLIC_URL` and `SETUP_TOKEN`. The container starts as root only to take ownership of the mounted volume, then drops to an unprivileged user before the server starts.

## Updating

The first unlock on this version gives existing messages persistent citation IDs inside `messages.db`. Back up the volume with the daemon stopped before upgrading. Rolling back to an older binary that only supports archive schema 1 requires restoring the matching backup.

WhatsApp changes its protocol regularly and stale clients stop connecting. The CI workflow probes for a newer `whatsmeow` every week. Deploys are manual in the Blueprint (`autoDeployTrigger: "off"`) so an update can be tried on one instance before the rest.
