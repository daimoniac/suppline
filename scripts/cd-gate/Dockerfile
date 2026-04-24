# Alpine + pinned Kyverno CLI for CI (official ghcr.io/kyverno/kyverno-cli has no shell).
#
# See README.md in this directory for build/push and KYVERNO_GATE_IMAGE.

FROM alpine:3.20
ARG KYVERNO_VERSION=1.17.1
RUN apk add --no-cache ca-certificates curl tar \
  && curl -fsSL -o /tmp/kyverno.tgz \
    "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/kyverno-cli_v${KYVERNO_VERSION}_linux_x86_64.tar.gz" \
  && tar -xzf /tmp/kyverno.tgz -C /usr/local/bin kyverno \
  && chmod +x /usr/local/bin/kyverno \
  && rm /tmp/kyverno.tgz \
  && apk del curl tar
