import type React from "react"
import type { Metadata } from "next"
import "./globals.css"

export const metadata: Metadata = {
  title: "PhishGuard | Phishing URL Scanner & Threat Intelligence",
  description:
    "Real-time dual-engine phishing URL scanner and threat intelligence console powered by VirusTotal and live urlscan.io browser sandboxing.",
  keywords: "phishing detector, URL scanner, security analysis, malware detection, VirusTotal, cybersecurity, threat intelligence",
  authors: [{ name: "Debasis Biswas", url: "https://urlchecker.debasisbiswas.in" }],
  creator: "Debasis Biswas",
  publisher: "Debasis Biswas",
  robots: "index, follow",
  openGraph: {
    title: "PhishGuard - Phishing URL Scanner",
    description: "Enterprise-grade URL threat analysis & live browser sandboxing",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "PhishGuard - Phishing URL Scanner",
    description: "Enterprise-grade URL threat analysis & live browser sandboxing",
  },
  icons: {
    icon: "/favicon.png",
    shortcut: "/favicon.png",
    apple: "/favicon.png",
  },
}

export const viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="font-sans antialiased min-h-screen bg-background text-foreground">
        {children}
      </body>
    </html>
  )
}
