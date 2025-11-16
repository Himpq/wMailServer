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

## Contributing

Issues and pull requests are welcome. Please include clear reproduction steps for bugs and focused patches for new features.

## License

No license file is included by default. Add a license if you plan to publish or redistribute.

---

If you want, I can add sample client configuration entries (Thunderbird/Outlook) and an SSL/TLS checklist.
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

## Contributing

Issues and pull requests are welcome. Please include clear reproduction steps for bugs and focused patches for new features.

## License

No license file is included by default. Add a license if you plan to publish or redistribute.

---

If you want, I can add sample client configuration entries (Thunderbird/Outlook) and an SSL/TLS checklist.
# wMailServer
A very simple mail system developed using Python. It only supports a few commands of POP3 and SMTP, which enables this software to handle emails.  
## wMailServer

A small, self-contained SMTP/POP3 mail server written in Python. wMailServer is designed for simplicity and easy deployment: it stores mail in the filesystem (no database), supports TLS, simple authentication, and basic mail relay.

### Key features
- SMTP server with EHLO/STARTTLS, AUTH (LOGIN/PLAIN over TLS), and message delivery (local and relay).
- POP3 server with AUTH, TOP, UIDL, LAST and optional implicit TLS (port 995) or explicit STLS (STARTTLS for POP3).
- Lightweight user management via `UserManager` and per-group configuration (`usermanager/<group>/group.json`).
- Mail relay support to forward outgoing mail to an upstream relay (useful when outbound port 25 is restricted).
- Simple DSN/notification generation for delivery failures and relay notifications.
- File-based storage: each message is stored under a per-user directory (no DB required).

### Quick start
1. Ensure Python 3.8+ is installed on the host.
2. Copy the repository to the server and edit `config/config.json` to set your services, ports and `UserGroups` certificate paths.
3. Make sure certificate files referenced by each user group exist and are readable by the process (if using TLS/SSL).
4. Start the server:

```bash
python3 wMailServer.py
```

5. The server will create required directories on first run; stop it, adjust the generated configuration files if needed, then restart.

### Configuration
- `config/config.json` contains services (SMTP/POP3), per-port SSL flags, and `UserGroups` settings including `sslCert` paths.
- `usermanager/<group>/group.json` controls the users and the domains bound to a user group.
- `sample/config` contains example configuration and templates you can copy and adapt.

### Security notes
- When using `AUTH PLAIN`, require TLS (PLAIN over TLS) to avoid sending credentials in cleartext.
- If you enable implicit SSL ports (e.g., 465 for SMTP, 995 for POP3) make sure the process actually loads the certificate and wraps the socket on accept. A common deployment mistake is to mark a port `ssl: true` in config but run the server without the corresponding certificate files — this will break TLS negotiation.

### Compatibility
- POP3 `CAPA` advertises supported extensions like `UTF8`. Some clients erroneously send `UTF8` as a standalone command; wMailServer accepts `UTF8` as a no-op for compatibility with such clients (e.g., Outlook).

### Development & extension
- The codebase is structured to be easy to extend: handlers for SMTP/POP3 commands are implemented as functions in `SMTPService.py` and `POP3Service.py`.
- An `IMAPService.py` placeholder is included for future IMAP support.

