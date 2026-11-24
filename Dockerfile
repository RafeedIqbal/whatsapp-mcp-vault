# syntax=docker/dockerfile:1

FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/whatsapp-mcp ./cmd/whatsapp-mcp

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime

# ffmpeg: only needed by send_audio_message for non-Opus input (see
# internal/media/audio.go); the tool degrades to a clear error without it,
# so it's not optional in this image but the binary itself would still run.
# ca-certificates: TLS to WhatsApp's servers.
RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
        ca-certificates \
        ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -m app
COPY --from=build /out/whatsapp-mcp /usr/local/bin/whatsapp-mcp
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && mkdir -p /home/app/store && chown -R app:app /home/app

WORKDIR /home/app

# The container starts as root only so the entrypoint can take ownership of a
# mounted data disk (hosts mount them root-owned); it then drops to the
# unprivileged user "app" before the server starts and cannot get root back.
#
# Loopback-only by default, matching the binary's own default. To host it, set:
#   WHATSAPP_MCP_ADDR=0.0.0.0:<port>   where to listen
#   WHATSAPP_MCP_ALLOW_REMOTE=1        allow connections from outside
#   PUBLIC_URL=https://...             the address clients use (Render sets
#                                      RENDER_EXTERNAL_URL, which is used if unset)
#   SETUP_TOKEN=<random>               one-time code the owner enters at /setup
# Do not set WHATSAPP_MCP_VAULT_KEY when hosting: the key is created at setup
# and never stored in usable form. See docs/hosting.md.
EXPOSE 8765
VOLUME ["/home/app/store"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["whatsapp-mcp", "healthcheck"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
