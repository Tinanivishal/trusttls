# TrustTLS - Easy SSL Certificate Tool

TrustTLS is a simple tool for getting SSL certificates. It works with both Let's Encrypt (free) and DigiCert (paid) certificates.

## What It Does

- 🚀 **Two Certificate Options**: Let's Encrypt (free) and DigiCert (paid)
- 🔐 **Automatic Setup**: Handles all the technical certificate stuff
- 🌐 **Web Server Ready**: Works with Apache and Nginx
- 📊 **Easy to Use**: Simple commands with clear progress
- 🔄 **Auto-Renewal**: Keeps your certificates updated
- 📁 **Safe Storage**: Saves certificates in standard folders

## How to Install

```bash
# Build from source
go build -o trusttls ./cmd/trusttls

# Or install directly
go install ./cmd/trusttls
```

## Get Started

### Let's Encrypt (Free Option)

```bash
# Basic use (finds your web server automatically)
trusttls install --domain example.com --email admin@example.com

# For Apache web server
trusttls install --web-server apache --domain example.com --email admin@example.com

# For Nginx web server
trusttls install --web-server nginx --domain example.com --email admin@example.com

# Say yes to everything (no questions)
trusttls install --domain example.com --email admin@example.com --yes
```

### DigiCert with ACME (Paid Option)

```bash
# Simple English flags
trusttls install \
  --web-server apache \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --digicert-key "<YOUR_KEY_ID>" \
  --digicert-secret "<YOUR_SECRET_KEY>" \
  --domain example.com \
  --email user@example.com \
  --yes

# With organization info
trusttls install \
  --web-server nginx \
  --cert-provider digicert \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --digicert-key "your-key-id" \
  --digicert-secret "your-secret-key" \
  --account-id "your-account-id" \
  --org-id "your-org-id" \
  --domain example.com \
  --email user@example.com
```

## Commands

### install

Get and set up an SSL certificate for your website.

```bash
trusttls install [options]
```

#### Main Options

| Option | What it does | Example |
|--------|-------------|---------|
| `--domain` | Website name | `example.com` |
| `--email` | Your email | `admin@example.com` |
| `--web-server` | Web server type | `apache` or `nginx` |
| `--apache` | Use Apache web server | `--apache` |
| `--nginx` | Use Nginx web server | `--nginx` |
| `--cert-provider` | Certificate company | `letsencrypt` or `digicert` |
| `--server` | Certificate server URL | `https://acme-v02.api.letsencrypt.org/directory` |
| `--digicert-key` | DigiCert key ID | `<YOUR_KEY_ID>` |
| `--digicert-secret` | DigiCert secret key | `<YOUR_SECRET_KEY>` |
| `--account-id` | DigiCert account ID | `your-account-id` |
| `--org-id` | DigiCert organization ID | `your-org-id` |
| `--yes` | Say yes to everything | `--yes` |
| `--key-type` | Key type: rsa or ecdsa | `ecdsa` |
| `--key-size` | Key size | `4096` |

### renew

Update all certificates that need to be renewed.

```bash
trusttls renew [--show-details]
```

## Works Like Certbot

TrustTLS works just like Certbot but with DigiCert support:

### Certbot Command
```bash
sudo certbot \
  --apache \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --eab-kid "<EAB_KID>" \
  --eab-hmac-key "<EAB_HMAC_KEY>" \
  --domain example.com \
  --agree-tos \
  --non-interactive \
  --email user@example.com
```

### TrustTLS Command
```bash
trusttls install \
  --apache \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --eab-kid "<EAB_KID>" \
  --eab-hmac-key "<EAB_HMAC_KEY>" \
  --domain example.com \
  --email user@example.com \
  --yes
```

## Why TrustTLS is Better

1. **No sudo needed**: Runs without special permissions
2. **Better display**: Clear progress and helpful messages
3. **Two options**: Both Let's Encrypt and DigiCert support
4. **Smart setup**: Saves your info for automatic updates
5. **Safe files**: Certificates saved in your home folder

## Where Files Are Saved

TrustTLS saves everything in your home folder:

```
~/.trusttls/
├── accounts/
│   ├── letsencrypt/
│   │   └── admin@example.com/
│   │       └── login-info.json
│   └── digicert/
│       └── admin@example.com/
│           └── login-info.json
├── live/
│   └── example.com/
│       ├── cert.pem          # Your website certificate
│       ├── chain.pem         # Middle certificate
│       ├── fullchain.pem     # Both certificates together
│       └── privkey.pem        # Your private key
├── archive/
│   └── example.com/
│       └── 20240104-120500/  # Old copies
└── renewal/
    └── example.com.yaml      # Update settings
```

## Web Server Setup

### Apache

TrustTLS sets up SSL for Apache automatically:

```apache
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /home/user/.trusttls/live/example.com/cert.pem
    SSLCertificateKeyFile /home/user/.trusttls/live/example.com/privkey.pem
    SSLCertificateChainFile /home/user/.trusttls/live/example.com/chain.pem
</VirtualHost>
</IfModule>
```

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /home/user/.trusttls/live/example.com/fullchain.pem;
    ssl_certificate_key /home/user/.trusttls/live/example.com/privkey.pem;
    ssl_trusted_certificate /home/user/.trusttls/live/example.com/chain.pem;
}
```

## Certificate Providers

### Let's Encrypt

- **Production**: `https://acme-v02.api.letsencrypt.org/directory`
- **Testing**: `https://acme-staging-v02.api.letsencrypt.org/directory`
- **No extra info needed**

### DigiCert ACME

- **Server URL**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
- **EAB KID**: Given by DigiCert
- **EAB HMAC Key**: Given by DigiCert

## More Examples

### Get Certificate and Private Key

```bash
# Create CSR and private key
trusttls generate-csr --domain example.com --email admin@example.com

# Use with DigiCert
trusttls install \
  --domain example.com \
  --email admin@example.com \
  --provider digicert \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --eab-kid "<EAB_KID>" \
  --eab-hmac-key "<EAB_HMAC_KEY>"
```

### Update Certificates

```bash
# Update all certificates
trusttls renew

# Show details while updating
trusttls renew --show-details

# Force update (ignore time)
trusttls renew --force
```

## Common Problems

### Issues You Might See

1. **Permission denied**: Make sure web server can read certificate files
2. **Web server not found**: Use `--apache` or `--nginx` to specify
3. **EAB info wrong**: Check your KID and HMAC key with DigiCert
4. **Domain check failed**: Make sure your domain points to this server

### Debug Mode

```bash
# Show more information
trusttls install --domain example.com --email admin@example.com --show-details

# Check setup
trusttls check --domain example.com
```

## Safety

- Private keys are kept safe (only you can read them)
- Account info is stored securely
- ACME checks use safe HTTP validation
- No special permissions needed

## Automatic Updates

### System Timer

```bash
# Set up automatic updates
sudo systemctl enable trusttls-updates.timer
sudo systemctl start trusttls-updates.timer
```

### Cron Job

```bash
# Add to daily schedule
0 2 * * * /usr/local/bin/trusttls renew --quiet
```

## Need Help?

- **Documentation**: [GitHub Wiki](https://github.com/trustctl/trusttls/wiki)
- **Report Issues**: [GitHub Issues](https://github.com/trustctl/trusttls/issues)
- **Community**: [Discord Server](https://discord.gg/trusttls)

## License

MIT License - see [LICENSE](LICENSE) file for details.
