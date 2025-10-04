"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Shield, AlertTriangle, CheckCircle, XCircle, Loader2, Search, Globe, Moon, Sun } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface ScanResult {
  url: string
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown"
  positives: number
  total: number
  scanDate: string
  permalink?: string
  details?: string
  scans?: Record<string, { detected: boolean; version: string; result: string; update: string }>
  rdap?: {
    domain: string
    registrar: string
    creation_date: string
    expiration_date: string
    name_servers: string[]
    status: string[]
    country: string
    organization: string
  }
}

export default function Home() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState("")
  const [darkMode, setDarkMode] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    // Check for saved theme preference or default to system preference
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
      localStorage.setItem("theme", "light")
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

  const normalizeUrl = (url: string): string => {
    const trimmedUrl = url.trim()

    // If URL already has protocol, return as is
    if (trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
      return trimmedUrl
    }

    // Add https:// by default
    return `https://${trimmedUrl}`
  }

  const validateUrl = (url: string): boolean => {
    try {
      new URL(normalizeUrl(url))
      return true
    } catch {
      return false
    }
  }

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!url.trim()) {
      setError("Please enter a URL to scan")
      return
    }

    if (!validateUrl(url)) {
      setError("Please enter a valid URL (e.g., example.com or https://example.com)")
      return
    }

    setLoading(true)
    setError("")
    setResult(null)

    try {
      const normalizedUrl = normalizeUrl(url)

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: normalizedUrl }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Failed to scan URL")
      }

      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred")
    } finally {
      setLoading(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case "safe":
        return "text-green-600 dark:text-green-400"
      case "suspicious":
        return "text-yellow-600 dark:text-yellow-400"
      case "malicious":
        return "text-red-600 dark:text-red-400"
      default:
        return "text-gray-600 dark:text-gray-400"
    }
  }

  const getThreatIcon = (level: string) => {
    switch (level) {
      case "safe":
        return <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
      case "suspicious":
        return <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
      case "malicious":
        return <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
      default:
        return <Shield className="h-5 w-5 text-gray-600 dark:text-gray-400" />
    }
  }

  if (!mounted) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-blue-900 dark:to-indigo-900 flex items-center justify-center">
        <div className="text-center">
          <div className="flex justify-center mb-4">
            <div className="p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full shadow-lg animate-pulse">
              <Shield className="h-10 w-10 text-white" />
            </div>
          </div>
          <div className="flex items-center justify-center gap-2 text-blue-600 dark:text-blue-400">
            <Loader2 className="h-5 w-5 animate-spin" />
            <span className="text-lg font-medium">Loading Security Scanner...</span>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-blue-900 dark:to-indigo-900 transition-all duration-500">
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto">
          {/* Theme Toggle */}
          <div className="flex justify-end mb-4">
            <Button
              variant="outline"
              size="icon"
              onClick={toggleTheme}
              className="hover-lift animate-fade-in bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700 hover:bg-white dark:hover:bg-gray-800"
            >
              {darkMode ? (
                <Sun className="h-4 w-4 transition-transform duration-300 text-yellow-500" />
              ) : (
                <Moon className="h-4 w-4 transition-transform duration-300 text-blue-600" />
              )}
              <span className="sr-only">Toggle theme</span>
            </Button>
          </div>

          {/* Header */}
          <div className="text-center mb-8 animate-fade-in">
            <div className="flex justify-center mb-4">
              <div className="p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full shadow-lg hover-lift animate-pulse-slow">
                <Shield className="h-10 w-10 text-white" />
              </div>
            </div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-2">
              Phishing URL Scanner
            </h1>
            <p className="text-gray-600 dark:text-gray-300 text-lg">
              Analyze URLs for potential phishing threats using VirusTotal
            </p>
          </div>

          {/* Scan Form */}
          <Card className="mb-6 hover-lift animate-slide-up glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                <Search className="h-5 w-5" />
                Enter URL to Scan
              </CardTitle>
              <CardDescription className="text-gray-600 dark:text-gray-400">
                Submit any URL to check for malicious content and phishing attempts
                <br />
                <span className="text-xs text-gray-500 dark:text-gray-500">
                  You can enter with or without http:// or https://
                </span>
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleScan} className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    type="text"
                    placeholder="example.com or https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="flex-1 transition-all duration-200 focus:scale-[1.02] focus:shadow-lg bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 text-gray-900 dark:text-gray-100"
                    disabled={loading}
                  />
                  <Button
                    type="submit"
                    disabled={loading || !url.trim()}
                    className="hover-lift transition-all duration-200 hover:scale-105 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>
              </form>

              {error && (
                <Alert className="mt-4 border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/50 animate-scale-in">
                  <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                  <AlertDescription className="text-red-800 dark:text-red-200">{error}</AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Results */}
          {result && (
            <div className="space-y-6 animate-fade-in">
              {/* Main Results Card */}
              <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                    {getThreatIcon(result.threatLevel)}
                    Scan Results
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">URL</label>
                      <p className="text-sm break-all font-mono text-gray-900 dark:text-gray-100">{result.url}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Threat Level</label>
                      <p className={`text-sm font-semibold capitalize ${getThreatColor(result.threatLevel)}`}>
                        {result.threatLevel}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Detection Ratio</label>
                      <p className="text-sm text-gray-900 dark:text-gray-100">
                        <span className="font-bold text-lg">{result.positives}</span> / {result.total} engines detected
                        threats
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Scan Date</label>
                      <p className="text-sm text-gray-900 dark:text-gray-100">{result.scanDate}</p>
                    </div>
                  </div>

                  {result.details && (
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Details</label>
                      <p className="text-sm text-gray-700 dark:text-gray-300">{result.details}</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* RDAP Information */}
              {result.rdap && (
                <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                      <Globe className="h-5 w-5" />
                      Domain Registration Information (RDAP)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {[
                        { label: "Domain", value: result.rdap.domain },
                        { label: "Registrar", value: result.rdap.registrar },
                        { label: "Organization", value: result.rdap.organization },
                        { label: "Country", value: result.rdap.country },
                        { label: "Creation Date", value: result.rdap.creation_date },
                        { label: "Expiration Date", value: result.rdap.expiration_date },
                      ].map((item, index) => (
                        <div
                          key={index}
                          className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200"
                        >
                          <label className="text-sm font-medium text-gray-500 dark:text-gray-400">{item.label}</label>
                          <p className="text-sm text-gray-900 dark:text-gray-100">{item.value}</p>
                        </div>
                      ))}
                    </div>

                    {result.rdap.name_servers && result.rdap.name_servers.length > 0 && (
                      <div className="mt-4">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Name Servers</label>
                        <div className="mt-2 space-y-2">
                          {result.rdap.name_servers.map((ns, index) => (
                            <p
                              key={index}
                              className="text-sm bg-gray-50 dark:bg-gray-700/50 px-3 py-2 rounded-lg font-mono hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200 text-gray-900 dark:text-gray-100"
                            >
                              {ns}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}

                    {result.rdap.status && result.rdap.status.length > 0 && (
                      <div className="mt-4">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Domain Status</label>
                        <div className="mt-2 space-y-2">
                          {result.rdap.status.map((status, index) => (
                            <p
                              key={index}
                              className="text-sm bg-blue-50 dark:bg-blue-950/50 px-3 py-2 rounded-lg text-blue-800 dark:text-blue-200 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors duration-200"
                            >
                              {status}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Detailed Scan Results */}
              {result.scans && Object.keys(result.scans).length > 0 && (
                <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                      <Search className="h-5 w-5" />
                      Detailed Scan Results ({Object.keys(result.scans).length} Engines)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {Object.entries(result.scans).map(([engine, scan]) => (
                        <div
                          key={engine}
                          className="flex items-center justify-between p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-all duration-200 hover:scale-[1.01]"
                        >
                          <div className="flex items-center gap-3">
                            {scan.detected ? (
                              <XCircle className="h-4 w-4 text-red-500 dark:text-red-400" />
                            ) : (
                              <CheckCircle className="h-4 w-4 text-green-500 dark:text-green-400" />
                            )}
                            <span className="font-medium text-sm text-gray-900 dark:text-gray-100">{engine}</span>
                          </div>
                          <div className="text-right">
                            {scan.detected ? (
                              <span className="text-red-600 dark:text-red-400 text-sm font-medium">{scan.result}</span>
                            ) : (
                              <span className="text-green-600 dark:text-green-400 text-sm font-medium">Clean</span>
                            )}
                            <p className="text-xs text-gray-500 dark:text-gray-400">v{scan.version}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Footer */}
          <div className="text-center mt-8 pt-8 border-t border-gray-200 dark:border-gray-700 animate-fade-in space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Made by Debasis Biswas | contact@debasisbiswas.me
            </p>
            <div className="text-xs text-gray-500 dark:text-gray-500 max-w-lg mx-auto leading-relaxed">
              <p className="mb-2">
                <strong>Policy:</strong> This tool uses the VirusTotal Public API for educational and research purposes
                only. It is not a replacement for antivirus software. All rights reserved by their respective owners.
              </p>
              <p>
                <a
                  href="https://docs.virustotal.com/docs/api-overview"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline transition-colors duration-200"
                >
                  VirusTotal API Documentation
                </a>
              </p>
              <p>
                <a
                  href="/privacy-policy"
                  className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline transition-colors duration-200"
                >
                  Privacy Policy
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
