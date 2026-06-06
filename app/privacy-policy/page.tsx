"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import { Shield, ArrowLeft, Mail, Lock, Database, EyeOff, Calendar, Moon, Sun } from "lucide-react"
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
      document.body.classList.add("dark")
    } else {
      document.documentElement.removeAttribute("data-theme")
      document.body.classList.remove("dark")
    }
  }, [])

  const toggleTheme = () => {
    const newDarkMode = !darkMode
    setDarkMode(newDarkMode)

    if (newDarkMode) {
      document.documentElement.setAttribute("data-theme", "dark")
      document.body.classList.add("dark")
      localStorage.setItem("theme", "dark")
    } else {
      document.documentElement.removeAttribute("data-theme")
      document.body.classList.remove("dark")
      localStorage.setItem("theme", "light")
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-blue-900 dark:to-indigo-900 transition-all duration-500 py-12 px-4">
      <div className="max-w-3xl mx-auto space-y-6">
        {/* Navigation & Theme Toggle */}
        <div className="flex justify-between items-center">
          <Link href="/" passHref>
            <Button
              variant="outline"
              size="sm"
              className="flex items-center gap-2 hover-lift bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700 hover:bg-white dark:hover:bg-gray-800 text-gray-700 dark:text-gray-200"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Scanner
            </Button>
          </Link>
          <Button
            variant="outline"
            size="icon"
            onClick={toggleTheme}
            className="hover-lift bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700 hover:bg-white dark:hover:bg-gray-800"
          >
            {darkMode ? (
              <Sun className="h-4 w-4 transition-transform duration-300 text-yellow-500" />
            ) : (
              <Moon className="h-4 w-4 transition-transform duration-300 text-blue-600" />
            )}
            <span className="sr-only">Toggle theme</span>
          </Button>
        </div>

        {/* Main Card */}
        <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700 shadow-xl">
          <CardHeader className="border-b border-gray-150 dark:border-gray-700 pb-6">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg text-blue-600 dark:text-blue-400">
                <Lock className="h-6 w-6" />
              </div>
              <div>
                <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  Privacy Policy
                </CardTitle>
                <CardDescription className="text-gray-600 dark:text-gray-400 flex items-center gap-2 mt-1">
                  <Calendar className="h-3.5 w-3.5" />
                  <span>Last updated: June 6, 2026</span>
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-6 pt-6 text-gray-700 dark:text-gray-300">
            <p className="leading-relaxed text-base">
              We value your privacy and are committed to protecting your personal information. This
              Privacy Policy explains what data we collect when you use the Phishing URL Scanner,
              and how we handle and protect it.
            </p>

            {/* Information We Collect */}
            <div className="space-y-3">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                <Database className="h-5 w-5 text-indigo-500" />
                Information We Collect
              </h2>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                When you submit a URL for verification, the following minimal connection and search
                parameters are logged:
              </p>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-1">
                {[
                  "User IP address (for rate limiting & abuse detection)",
                  "Device type and browser user-agent details",
                  "Timestamp of the search execution",
                  "The queried URL or domain address",
                ].map((item, index) => (
                  <li
                    key={index}
                    className="flex items-start gap-2.5 p-3 rounded-lg bg-gray-50 dark:bg-gray-900/40 border border-gray-150 dark:border-gray-800 text-sm"
                  >
                    <span className="h-2 w-2 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Purpose of Data Collection */}
            <div className="space-y-2.5">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                <Shield className="h-5 w-5 text-emerald-500" />
                Purpose of Data Collection
              </h2>
              <p className="leading-relaxed text-sm">
                The collected information is used solely for essential security operations. This
                includes identifying automated abuse or scraping patterns, preventing malicious
                payload injection, and refining the scanning algorithm. No profile tracking or
                advertisement analytics are active.
              </p>
            </div>

            {/* Data Sharing */}
            <div className="space-y-2.5">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                <EyeOff className="h-5 w-5 text-rose-500" />
                Data Sharing & Confidentiality
              </h2>
              <p className="leading-relaxed text-sm">
                We strictly do <strong>not</strong> share, sell, or disclose your IP addresses or
                history details to any third-party marketing networks or analytics providers. All
                information resides securely on internal servers used strictly for standard security
                assessment logs.
              </p>
            </div>

            {/* Contact */}
            <div className="pt-4 border-t border-gray-150 dark:border-gray-700 space-y-3">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Contact & Inquiries
              </h2>
              <p className="text-sm">
                If you have questions regarding this privacy policy or wish to submit feedback,
                please reach out to our security team:
              </p>
              <a
                href="mailto:security@debasisbiswas.in"
                className="inline-flex items-center gap-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline hover:text-blue-800 dark:hover:text-blue-300 transition-colors"
              >
                <Mail className="h-4 w-4" />
                security@debasisbiswas.in
              </a>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center text-xs text-gray-500 dark:text-gray-400 pt-4">
          <p>© {new Date().getFullYear()} Phishing URL Scanner. All rights reserved.</p>
        </div>
      </div>
    </div>
  )
}
