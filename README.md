# wMailServer

A very simple mail system developed using Python. It only supports core SMTP and POP3 features and is built for easy deployment and local testing. The server stores mail on disk (no database required), supports TLS, basic authentication, and simple relay capabilities.

## Key features

- SMTP with EHLO/STARTTLS and authentication (LOGIN and PLAIN over TLS).
- POP3 with AUTH, TOP, UIDL, LAST, and optional implicit TLS (port 995) or explicit STLS.
- File-based mail storage per user (no DB).
- Mail relay support to send outgoing mail through an upstream relay when direct delivery is unavailable.
- Simple DSN/notifications for delivery status and failures.
- Lightweight per-group user management (`usermanager/<group>/group.json`).

## Quick start

1. Install Python 3.8+ on your host.
2. Edit `config/config.json` to configure SMTP/POP3 services, ports and `UserGroups` certificate paths.
3. Make sure any certificate files referenced in `UserGroups` exist and are readable by the process when TLS is enabled.
4. Start the server:

```bash
python3 wMailServer.py
```

5. On first run the server creates required directories; stop it, review and update any generated configs, then restart.

## Configuration

- `config/config.json` contains service port definitions, SSL flags and user-group mappings.
- `usermanager/<group>/group.json` stores users and domain bindings for each group.
- `sample/config` includes example config and template files to copy and adapt.

## Security notes

- Always require TLS for AUTH PLAIN (credentials must not be sent in cleartext).
- If you enable implicit SSL ports (e.g. 465 or 995), ensure certificate paths are correct and the server process can access them; otherwise TLS negotiation will fail.

## Compatibility

- POP3 `CAPA` advertises extensions such as `UTF8`. Some clients may send `UTF8` as a command — wMailServer accepts `UTF8` as a no-op for compatibility with such clients (for example Outlook).

## Development & extension

- Command handlers live in `SMTPService.py` and `POP3Service.py` and are straightforward to extend.
- An `IMAPService.py` placeholder exists as a starting point for future IMAP support.

