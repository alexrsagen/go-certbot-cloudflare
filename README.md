# go-certbot-cloudflare
A helper to automate Certbot domain authentication using the DNS challenge with Cloudflare as DNS provider.

## Usage
The application, with executables downloadable from GitHub releases, should be used in the Certbot command-line flags `--manual-auth-hook` and `--manual-cleanup-hook`.

Info/debug-level output may be obtained by passing the `-verbose` flag.

Cleanup mode is set by passing the `-cleanup` flag. This should be used in the `--manual-cleanup-hook` of certbot.

### Example
```
CF_API_EMAIL="you@example.com" CF_API_KEY="xxxxx" /opt/certbot/certbot-auto renew --server https://acme-v02.api.letsencrypt.org/directory --manual --manual-auth-hook="/path/to/go-certbot-cloudflare" --manual-cleanup-hook="/path/to/go-certbot-cloudflare -cleanup" --manual-public-ip-logging-ok --preferred-challenges dns
```
