FROM alpine:3.20 AS builder

ARG MC_VERSION=latest
ARG VAULT_VERSION=1.15.4

RUN apk add --no-cache curl unzip

RUN curl -s -o /usr/local/bin/mc https://dl.min.io/client/mc/release/linux-amd64/mc \
    && chmod +x /usr/local/bin/mc

RUN curl -s -O https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip \
    && unzip vault_${VAULT_VERSION}_linux_amd64.zip \
    && mv vault /usr/local/bin/vault \
    && chmod +x /usr/local/bin/vault

FROM alpine:3.20

RUN apk add --no-cache ca-certificates libc6-compat

COPY --from=builder /usr/local/bin/mc /usr/local/bin/mc
COPY --from=builder /usr/local/bin/vault /usr/local/bin/vault

CMD ["sh"]