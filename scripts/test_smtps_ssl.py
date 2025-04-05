#!/usr/bin/env python3
"""
Simple SMTPS (implicit TLS) tester for a mail server.

Usage:
  python3 scripts/test_smtps_ssl.py --host mail.himpqblog.cn --port 465 [--insecure]

What it does:
- Create a TCP connection to host:port
- Establish SSL/TLS immediately (implicit SMTPS)
- Print peer certificate subject/issuer/validity
- Read SMTP banner
- Send EHLO and print responses
- Send QUIT

Options:
  --host HOST     target hostname (default: mail.himpqblog.cn)
  --port PORT     target port (default: 465)
  --timeout SEC   network timeout in seconds (default: 10)
  --insecure      do not verify server certificate (useful for testing)

"""

import socket
import ssl
import sys
import argparse


def main():
    p = argparse.ArgumentParser(description='SMTPS implicit TLS tester')
    p.add_argument('--host', default='mail.himpqblog.cn')
    p.add_argument('--port', type=int, default=465)
    p.add_argument('--timeout', type=float, default=10.0)
    p.add_argument('--insecure', action='store_true')
    args = p.parse_args()

    host = args.host
    port = args.port

    context = ssl.create_default_context()
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    conn = None
    try:
        print(f"Connecting to {host}:{port} (timeout {args.timeout}s) ...")
        raw = socket.create_connection((host, port), timeout=args.timeout)
        raw.settimeout(args.timeout)

        print("Starting TLS handshake...")
        s = context.wrap_socket(raw, server_hostname=host)
        conn = s

        # Attempt to fetch peer certificate (both parsed and raw DER)
        cert = None
        try:
            cert = s.getpeercert()
        except Exception:
            cert = None

        if cert:
            subject = cert.get('subject', ())
            issuer = cert.get('issuer', ())
            notBefore = cert.get('notBefore')
            notAfter = cert.get('notAfter')
            print("Peer certificate:")
            print("  subject:")
            for comp in subject:
                print("    ", comp)
            print("  issuer:")
            for comp in issuer:
                print("    ", comp)
            print(f"  valid: {notBefore} -> {notAfter}")
        else:
            print("No parsed peer certificate returned by getpeercert()")

        # Try binary form (DER) and convert to PEM for inspection if available
        try:
            der = s.getpeercert(binary_form=True)
            if der:
                try:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    print('\nPeer certificate (PEM):\n')
                    print(pem)
                except Exception:
                    print('Peer certificate present (DER) but failed to convert to PEM')
            else:
                print('No peer certificate in binary form (getpeercert(binary_form=True) returned None)')
        except Exception as e:
            print('getpeercert(binary_form=True) error:', e)

        # Print negotiated protocol/cipher for debugging
        try:
            print('TLS version:', s.version())
            print('Cipher:', s.cipher())
            try:
                print('ALPN protocol:', s.selected_alpn_protocol())
            except Exception:
                pass
        except Exception:
            pass

        # read banner
        print("Reading banner...")
        f = s.makefile('r', encoding='utf-8', newline='\r\n')
        banner = f.readline()
        print("Banner:", repr(banner))

        # EHLO
        ehlo_name = 'test.example.com'
        print("Sending EHLO...")
        s.sendall(f"EHLO {ehlo_name}\r\n".encode('utf-8'))
        while True:
            line = f.readline()
            if not line:
                break
            print("EHLO=>", repr(line))
            if line.startswith('250 '):
                break

        print("Sending QUIT...")
        s.sendall(b"QUIT\r\n")
        try:
            q = f.readline()
            print("QUIT=>", repr(q))
        except Exception:
            pass

    except Exception as e:
        print("Error:", e)
        sys.exit(2)
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
