# TrustTLS - SSL Certificate Management Tool

TrustTLS is a modern SSL certificate management tool that supports both Let's Encrypt and DigiCert certificates with behavior similar to Certbot.

## Features

- 🚀 **Dual Provider Support**: Let's Encrypt (free) and DigiCert (commercial)
- 🔐 **ACME Protocol**: Full ACME compliance with External Account Binding (EAB)
- 🌐 **Web Server Integration**: Apache and Nginx plugin support
- 📊 **Interactive CLI**: Beautiful progress indicators and user-friendly interface
- 🔄 **Automatic Renewal**: Seamless certificate renewal with stored credentials
- 📁 **Standard Paths**: Certificates stored in standard locations (not in root)

## Installation

```bash
# Build from source
go build -o trusttls ./cmd/trusttls

# Or install directly
go install ./cmd/trusttls
```

## Quick Start

### Let's Encrypt (Default)

```bash
# Basic usage (auto-detects web server)
trusttls install --domain example.com --email admin@example.com

# With Apache plugin (like certbot --apache)
trusttls install --apache --domain example.com --email admin@example.com

# With Nginx plugin (like certbot --nginx)
trusttls install --nginx --domain example.com --email admin@example.com

# Non-interactive mode
trusttls install --domain example.com --email admin@example.com --yes
```

### DigiCert with ACME EAB (like certbot)

```bash
# Exact equivalent to certbot command
trusttls install \
  --apache \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --eab-kid "<EAB_KID>" \
  --eab-hmac-key "<EAB_HMAC_KEY>" \
  --domain example.com \
  --agree-tos \
  --non-interactive \
  --email user@example.com

# With interactive mode
trusttls install \
  --apache \
  --server https://one.digicert.com/mpki/api/v1/acme/v2/directory \
  --eab-kid "your-kid-here" \
  --eab-hmac-key "your-hmac-key-here" \
  --domain example.com \
  --email user@example.com
```

## Command Reference

### install

Install SSL certificate for a domain.

```bash
trusttls install [flags]
```

#### Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--domain` | Domain to issue certificate for | `example.com` |
| `--email` | Account email | `admin@example.com` |
| `--apache` | Use Apache plugin (like certbot --apache) | `--apache` |
| `--nginx` | Use Nginx plugin (like certbot --nginx) | `--nginx` |
| `--server` | ACME directory URL | `https://acme-v02.api.letsencrypt.org/directory` |
| `--eab-kid` | EAB Key ID for DigiCert | `<EAB_KID>` |
| `--eab-hmac-key` | EAB HMAC Key for DigiCert | `<EAB_HMAC_KEY>` |
| `--staging` | Use Let's Encrypt staging | `--staging` |
| `--yes` | Non-interactive mode | `--yes` |
| `--key-type` | Key algorithm: rsa or ecdsa | `ecdsa` |
| `--key-size` | Key size | `4096` |

### renew

Renew all certificates due for renewal.

```bash
trusttls renew [--verbose]
```

## Certbot Compatibility

TrustTLS is designed to be a drop-in replacement for Certbot with DigiCert ACME support:

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

### TrustTLS Equivalent
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

## Key Differences from Certbot

1. **No sudo required**: TrustTLS runs without root privileges
2. **Better UI**: Interactive progress indicators and clear error messages
3. **Dual provider**: Built-in support for both Let's Encrypt and DigiCert
4. **Account management**: Secure credential storage for automatic renewal
5. **Standard paths**: Certificates stored in user directory, not root

## File Structure

TrustTLS stores all data in the user's home directory:

```
~/.trusttls/
├── accounts/
│   ├── letsencrypt/
│   │   └── admin@example.com/
│   │       └── credentials.json
│   └── digicert/
│       └── admin@example.com/
│           └── credentials.json
├── live/
│   └── example.com/
│       ├── cert.pem          # Server certificate
│       ├── chain.pem         # Intermediate certificate
│       ├── fullchain.pem     # Full chain (cert + intermediate)
│       └── privkey.pem        # Private key
├── archive/
│   └── example.com/
│       └── 20240104-120500/  # Timestamped backup
└── renewal/
    └── example.com.yaml      # Renewal configuration
```

## Web Server Configuration

### Apache

TrustTLS automatically creates SSL virtual host configurations:

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

## Provider Configuration

### Let's Encrypt

- **Production**: `https://acme-v02.api.letsencrypt.org/directory`
- **Staging**: `https://acme-staging-v02.api.letsencrypt.org/directory`
- **No additional credentials required**

### DigiCert ACME

- **Directory URL**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
- **EAB KID**: Provided by DigiCert
- **EAB HMAC Key**: Provided by DigiCert

## Advanced Usage

### Manual CSR Generation

```bash
# Generate CSR and private key
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

### Certificate Renewal

```bash
# Renew all certificates
trusttls renew

# Renew with verbose output
trusttls renew --verbose

# Force renewal (ignores expiry time)
trusttls renew --force
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure web server can access certificate files
2. **Web server not detected**: Use `--apache` or `--nginx` flags explicitly
3. **EAB credentials invalid**: Verify KID and HMAC key with DigiCert
4. **Domain validation failed**: Ensure domain points to server and webroot is accessible

### Debug Mode

```bash
# Enable verbose logging
trusttls install --domain example.com --email admin@example.com --verbose

# Check configuration
trusttls check --domain example.com
```

## Security

- Private keys are stored with 600 permissions
- Account credentials are encrypted at rest
- ACME challenges use secure HTTP validation
- No root privileges required

## Integration

### Systemd Timer

```bash
# Create renewal timer
sudo systemctl enable trusttls-renewal.timer
sudo systemctl start trusttls-renewal.timer
```

### Cron Job

```bash
# Add to crontab for daily renewal
0 2 * * * /usr/local/bin/trusttls renew --quiet
```

## Support

- **Documentation**: [GitHub Wiki](https://github.com/trustctl/trusttls/wiki)
- **Issues**: [GitHub Issues](https://github.com/trustctl/trusttls/issues)
- **Community**: [Discord Server](https://discord.gg/trusttls)

## License

MIT License - see [LICENSE](LICENSE) file for details.
