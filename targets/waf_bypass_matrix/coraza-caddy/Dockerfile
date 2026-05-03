FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# CRS rules
RUN apk add --no-cache git && \
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git /etc/coraza/crs && \
    apk del git

COPY Caddyfile /etc/caddy/Caddyfile
COPY coraza.conf /etc/coraza/coraza.conf

EXPOSE 8080
