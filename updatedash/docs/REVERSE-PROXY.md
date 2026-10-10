# Putting updatedash behind Nginx Proxy Manager or Traefik

The dashboard listens on `https://<dashboard-ip>:8099` (a self-signed certificate when `tls: auto`).
A proxy gives it a real name and a trusted certificate. Three settings must agree:

| Where | Setting | Why |
|---|---|---|
| Dashboard `/etc/updatedash/config.yaml` | `trust_proxy: ["<proxy IP>"]` | Only then are `X-Forwarded-For/Proto/Host` believed: the real client IP for the lockout and audit log, the `Secure` cookie, and the Origin check. |
| Dashboard config | `allow_from: [...]` (optional) | Applies to the **real client** address once `trust_proxy` is set. |
| Proxy | forward `Host` (or `X-Forwarded-Host`), `X-Forwarded-For`, `X-Forwarded-Proto` | The dashboard compares the browser's `Origin` with the public host name and refuses mismatches. |

After editing the config: `systemctl restart updatedash`. The banner "requests arrive through a proxy but `trust_proxy` is not set"
in the dashboard means the first setting is missing.

## Nginx Proxy Manager

1. **Hosts → Proxy Hosts → Add**: Domain `updates.example.net`.
2. **Scheme `https`**, Forward Hostname/IP = the dashboard IP, Port `8099`. (If you set `tls: off`, use `http`.)
   Scheme `http` against a TLS-enabled dashboard returns a 400/502.
3. Turn on **Websockets Support** (harmless) and **Block Common Exploits**.
4. **SSL** tab: request a Let's Encrypt certificate (DNS challenge works for LAN-only names), **Force SSL**, **HTTP/2**, **HSTS**.
5. **Advanced** tab (the defaults already forward the headers; this only makes the self-signed upstream explicit and adds a timeout for long update logs):
   ```nginx
   proxy_read_timeout 120s;
   proxy_set_header X-Forwarded-Host $host;
   ```
   NPM verifies upstream certificates only if you add `proxy_ssl_verify on;` – by default it does not, so the self-signed certificate is accepted.
6. Dashboard config: `trust_proxy: ["<NPM container IP>"]`, restart.
7. For access from the LAN only, use an NPM **Access List** (or `allow_from` on the dashboard) rather than publishing the name.

## Traefik (file provider)

Traefik refuses an untrusted backend certificate, so describe the backend with a `serversTransport`:

```yaml
# /etc/traefik/conf.d/updatedash.yml
http:
  routers:
    updatedash:
      rule: Host(`updates.example.net`)
      entryPoints: [websecure]
      service: updatedash
      tls:
        certResolver: letsencrypt        # whatever yours is called
      middlewares: [updatedash-headers]
  middlewares:
    updatedash-headers:
      headers:
        stsSeconds: 31536000
        # Traefik already sends X-Forwarded-For/Proto/Host; nothing else is required
  services:
    updatedash:
      loadBalancer:
        serversTransport: updatedash-tls
        servers:
          - url: "https://10.10.56.16:8099"
  serversTransports:
    updatedash-tls:
      insecureSkipVerify: true           # simplest; the backend is your own LXC
      # stricter: trust the dashboard's certificate instead
      # rootCAs: [/etc/traefik/updatedash-cert.pem]
      # serverName: updatedash
```

* `insecureSkipVerify: true` skips verification of the **backend** only. For the stricter form copy
  `/var/lib/updatedash/tls/tls.crt` from the dashboard container and use `rootCAs` plus `serverName` (a name in the certificate; add one with `tls_names:` in the config and restart).
* If you switched the dashboard to `tls: off`, use `url: "http://10.10.56.16:8099"` and drop the transport.
* Dashboard config: `trust_proxy: ["<Traefik container IP>"]`, restart. With Docker, use the address Traefik connects from.
* Make sure Traefik's `forwardedHeaders.trustedIPs` (entry point) is **not** set to `0.0.0.0/0` if the dashboard is reachable from the internet.

## Checks

```bash
curl -sI https://updates.example.net/healthz | head -1          # HTTP/2 200
curl -s  https://updates.example.net/healthz                    # ok
```
Sign in, open **Settings → General → About** and confirm it says the connection is HTTPS; the dashboard shows no proxy warning.

| Symptom | Cause |
|---|---|
| 502 / 400 from the proxy | Scheme mismatch (`http` to a `tls: auto` dashboard), or Traefik rejecting the self-signed certificate. |
| "Cross-site request refused" when signing in | The `Origin` host differs from the host the dashboard sees: forward `Host`/`X-Forwarded-Host`, and set `trust_proxy`. |
| Everyone shows as the proxy's IP, lockout hits all users | `trust_proxy` missing or wrong IP. |
| Signed out on every request | Cookie is `Secure` but the browser reached it over plain http; use the https name. |
| Theme background missing on the sign-in page | A proxy rule blocks `/theme.css`; it is public by design and contains only colours. |
