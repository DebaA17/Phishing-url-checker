import { NextResponse } from "next/server"

export async function GET() {
  const policy = `
# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this application, please report it to:

**Email:** forensic@debasisbiswas.me

## What to Include

When reporting a security issue, please include:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (if available)

## Response Timeline

- **Acknowledgment:** Within 24 hours
- **Initial Assessment:** Within 72 hours
- **Resolution:** Varies based on severity

## Scope

This security policy applies to:
- The main application (URL Scanner)
- All API endpoints
- Client-side components

## Out of Scope

- Third-party services (VirusTotal, Telegram)
- Infrastructure provided by Vercel
- Social engineering attacks

## Responsible Disclosure

We follow responsible disclosure practices:
1. Report the issue privately
2. Allow reasonable time for fixes
3. Coordinate public disclosure

Thank you for helping keep our application secure!

---
Contact: forensic@debasisbiswas.me
Last Updated: ${new Date().toISOString().split("T")[0]}
  `.trim()

  return new NextResponse(policy, {
    headers: {
      "Content-Type": "text/plain",
    },
  })
}
