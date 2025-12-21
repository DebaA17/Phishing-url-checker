import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Phishing URL Scanner - Security Analysis Tool",
  description:
    "Advanced AI-powered phishing URL scanner using VirusTotal API. Analyze URLs for potential threats, malware, and phishing attempts.",
  keywords: "phishing, URL scanner, security, malware detection, VirusTotal, cybersecurity",
  authors: [{ name: "Debasis Biswas", url: "https://urlcheck.debasisbiswas.me" }],
  creator: "Debasis Biswas",
  publisher: "Debasis Biswas",
  robots: "index, follow",
  openGraph: {
    title: "Phishing URL Scanner",
    description: "Advanced AI-powered phishing URL scanner using VirusTotal API",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "Phishing URL Scanner",
    description: "Advanced AI-powered phishing URL scanner using VirusTotal API",
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
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  )
}
