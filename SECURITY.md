# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it by creating an issue or contacting the maintainer directly at forensic@debasisbiswas.me.

- Do not disclose security issues publicly until they have been reviewed and patched.
- Provide as much detail as possible to help reproduce and address the issue.

## PGP Public Key

If you would like to submit an encrypted message (for example, to share sensitive details), import my public key and encrypt your message before sending.

To import the public key run:

```bash
# import the public key
curl -s "https://keys.openpgp.org/vks/v1/by-fingerprint/B521D1095C63E077EAE854E96805708F78A19272" | gpg --import
```

The key fingerprint is: `B521D1095C63E077EAE854E96805708F78A19272` — verify this before trusting the key.

## Supported Versions

| Version | Supported          |
| ------- | ----------------- |
| main    | :white_check_mark:|

## Security Updates

Security updates will be prioritized and released as soon as possible after a vulnerability is confirmed.

## Responsible Disclosure

We appreciate responsible disclosure and will make every effort to address reported issues promptly.
