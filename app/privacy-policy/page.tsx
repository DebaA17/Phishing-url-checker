"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import {
  Shield,
  ShieldCheck,
  ArrowLeft,
  Mail,
  Lock,
  Database,
  EyeOff,
  Calendar,
  Moon,
  Sun,
  Server,
  FileCheck,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export default function PrivacyPolicyPage() {
  const [darkMode, setDarkMode] = useState(false)

  useEffect(() => {
    const savedTheme = localStorage.getItem("theme")
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches
    const shouldUseDark = savedTheme === "dark" || (!savedTheme && prefersDark)
    setDarkMode(shouldUseDark)

    if (shouldUseDark) {
      document.documentElement.setAttribute("data-theme", "dark")
      document.documentElement.classList.add("dark")
      document.body.classList.add("dark")
    } else {
      document.documentElement.removeAttribute("data-theme")
      document.documentElement.classList.remove("dark")
      document.body.classList.remove("dark")
    }
  }, [])

  const toggleTheme = () => {
    const newDarkMode = !darkMode
    setDarkMode(newDarkMode)

    if (newDarkMode) {
      document.documentElement.setAttribute("data-theme", "dark")
      document.documentElement.classList.add("dark")
      document.body.classList.add("dark")
      localStorage.setItem("theme", "dark")
    } else {
      document.documentElement.removeAttribute("data-theme")
      document.documentElement.classList.remove("dark")
      document.body.classList.remove("dark")
      localStorage.setItem("theme", "light")
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground cyber-grid transition-colors duration-200">
      {/* Top Header */}
      <header className="sticky top-0 z-40 w-full border-b border-border/80 bg-background/90 backdrop-blur-md">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="inline-flex items-center gap-2 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="h-4 w-4" />
            <span>Back to Security Scanner</span>
          </Link>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={toggleTheme}
              className="h-9 w-9 rounded-md border-border bg-card hover:bg-muted"
            >
              {darkMode ? (
                <Sun className="h-4 w-4 text-amber-400" />
              ) : (
                <Moon className="h-4 w-4 text-slate-700" />
              )}
              <span className="sr-only">Toggle theme</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-10 space-y-6">
        <Card className="border-border shadow-sm bg-card">
          <CardHeader className="border-b border-border/60 pb-6">
            <div className="flex items-center gap-3 mb-2">
              <div className="h-10 w-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-500">
                <Lock className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-2xl font-bold tracking-tight text-foreground">
                  Privacy Policy & Data Security
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground flex items-center gap-2 mt-1 font-mono">
                  <Calendar className="h-3.5 w-3.5" />
                  <span>Last updated: November 2026</span>
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-6 pt-6 text-foreground text-sm leading-relaxed">
            <p className="text-muted-foreground">
              PhishGuard is built for defensive cybersecurity research, triage, and threat mitigation.
              This Privacy Policy explains what telemetry is collected when you submit URLs for verification,
              how third-party scanning engines interact with queries, and how we protect confidentiality.
            </p>

            {/* Information We Collect */}
            <div className="space-y-3 pt-2">
              <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                <Database className="h-4 w-4 text-sky-500" />
                Information We Collect & Process
              </h2>
              <p className="text-xs text-muted-foreground">
                When a scan is dispatched, the following telemetry is transmitted through our edge infrastructure:
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  { title: "Submitted URL / Domain", desc: "Parsed and normalized for VirusTotal & urlscan.io queries." },
                  { title: "Client IP Address", desc: "Retained ephemerally for rate limiting & automated abuse prevention." },
                  { title: "Browser User-Agent", desc: "Evaluated to prevent bot scraping and brute-force traffic." },
                  { title: "Verification Tokens", desc: "Cloudflare Turnstile cryptographically validates human requests." },
                ].map((item, idx) => (
                  <div key={idx} className="p-3 rounded-lg border border-border bg-muted/30">
                    <p className="text-xs font-semibold text-foreground">{item.title}</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{item.desc}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Third-Party Threat Engines */}
            <div className="space-y-3 pt-2">
              <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                <Server className="h-4 w-4 text-emerald-500" />
                Third-Party Security Vendors & Feeds
              </h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                To provide comprehensive detection, your target URL is dispatched to:
              </p>
              <ul className="space-y-2 text-xs text-muted-foreground list-disc pl-5">
                <li>
                  <strong className="text-foreground">VirusTotal (Google Cloud):</strong> URLs are queried against 90+ antivirus and anti-phishing vendors.
                </li>
                <li>
                  <strong className="text-foreground">urlscan.io:</strong> A headless Chromium browser navigates to the target page in an isolated sandbox. When Public Visibility is selected, results may be viewable in the public urlscan.io stream. When Private Visibility is selected, the scan remains unlisted.
                </li>
              </ul>
            </div>

            {/* No Data Brokerage */}
            <div className="space-y-2 pt-2">
              <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                <EyeOff className="h-4 w-4 text-rose-500" />
                Zero Data Brokerage & Tracking
              </h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                We do not sell, rent, or monetize your search history, IP addresses, or audited URLs. No cross-site marketing trackers, pixels, or third-party advertising cookies are present on this site.
              </p>
            </div>

            {/* Contact */}
            <div className="pt-4 border-t border-border space-y-2">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Mail className="h-4 w-4 text-sky-500" />
                Security & Contact Inquiries
              </h2>
              <p className="text-xs text-muted-foreground">
                For questions regarding data processing, security disclosures, or takedown requests, contact:
              </p>
              <a
                href="mailto:contact@debasisbiswas.in"
                className="inline-flex items-center gap-1.5 text-xs font-mono font-medium text-sky-500 hover:text-sky-400 hover:underline"
              >
                contact@debasisbiswas.in
              </a>
            </div>
          </CardContent>
        </Card>
      </main>

      <footer className="mt-12 py-6 border-t border-border text-center text-xs text-muted-foreground">
        <p>© {new Date().getFullYear()} PhishGuard Security. All rights reserved.</p>
      </footer>
    </div>
  )
}
