"use client"

import type React from "react"

import { useState, useEffect, useRef } from "react"
import Image from "next/image"
import Script from "next/script"
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Search,
  Globe,
  Moon,
  Sun,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { AspectRatio } from "@/components/ui/aspect-ratio"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Skeleton } from "@/components/ui/skeleton"

declare global {
  interface Window {
    turnstile?: {
      render: (container: string | HTMLElement, options: Record<string, unknown>) => string
      reset: (widgetId?: string) => void
      remove?: (widgetId: string) => void
    }
  }
}

interface VirusTotalScanResult {
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

type UrlscanVisibility = "public" | "private"

interface UrlscanSubmitResponse {
  uuid: string
  result?: string
  api?: string
  visibility?: string
  message?: string
}

type UrlscanMetaProcessorData = {
  applications?: unknown[]
  technologies?: unknown[]
}

type UrlscanMetaProcessors = {
  wappalyzer?: { data?: UrlscanMetaProcessorData }
  wappa?: { data?: UrlscanMetaProcessorData }
}

type UrlscanResult = {
  page?: {
    ip?: string
    country?: string
    asnname?: string
    asn?: string
    domain?: string
    url?: string
    title?: string
    server?: string
  }
  task?: {
    url?: string
    time?: string
    country?: string
  }
  stats?: {
    uniqIPs?: number
    uniqCountries?: number
    uniqDomains?: number
    requests?: number
  }
  verdicts?: Record<string, unknown>
  meta?: {
    processors?: UrlscanMetaProcessors
  }
  data?: {
    requests?: unknown[]
    links?: unknown[]
  }
  lists?: {
    domains?: unknown[]
    ips?: unknown[]
    urls?: unknown[]
  }
}

interface CombinedScanResponse {
  virusTotal: VirusTotalScanResult | null
  virusTotalError: string | null
  liveSubmit: UrlscanSubmitResponse | null
  liveError: string | null
  error?: string
}

function asStringArray(value: unknown): string[] {
  if (!value) return []
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string")
  return []
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

function toText(value: unknown): string {
  if (value === null || value === undefined) return "—"
  if (typeof value === "string" && value.trim().length > 0) return value
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  return "—"
}

function toOptionalText(value: unknown): string | null {
  const t = toText(value)
  return t === "—" ? null : t
}

function scoreBadgeVariant(
  score: unknown,
  malicious: unknown,
): "default" | "secondary" | "destructive" | "outline" {
  const isMalicious = malicious === true
  if (isMalicious) return "destructive"
  if (typeof score === "number" && score >= 50) return "destructive"
  if (typeof score === "number" && score > 0) return "secondary"
  return "outline"
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  const s = status.toLowerCase()
  if (s.includes("complete")) return "default"
  if (s.includes("processing") || s.includes("queued") || s.includes("submitting"))
    return "secondary"
  if (s.includes("fail") || s.includes("error") || s.includes("timeout")) return "destructive"
  return "outline"
}

export default function Home() {
  const turnstileSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "0x4AAAAAACp9k1gSv25NYbw7"
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [virusTotalResult, setVirusTotalResult] = useState<VirusTotalScanResult | null>(null)
  const [urlscanSubmit, setUrlscanSubmit] = useState<UrlscanSubmitResponse | null>(null)
  const [urlscanResult, setUrlscanResult] = useState<UrlscanResult | null>(null)
  const [urlscanVisibility, setUrlscanVisibility] = useState<UrlscanVisibility>("public")
  const [urlscanStatus, setUrlscanStatus] = useState("")
  const [virusTotalError, setVirusTotalError] = useState("")
  const [liveScanError, setLiveScanError] = useState("")
  const [screenshotRefreshKey, setScreenshotRefreshKey] = useState(0)
  const [screenshotLoading, setScreenshotLoading] = useState(false)
  const [screenshotError, setScreenshotError] = useState(false)
  const [error, setError] = useState("")
  const [darkMode, setDarkMode] = useState(false)
  const [turnstileScriptLoaded, setTurnstileScriptLoaded] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState("")
  const widgetIdRef = useRef<string | null>(null)

  const pollingRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!turnstileScriptLoaded || !turnstileSiteKey || !window.turnstile || widgetIdRef.current) {
      return
    }

    widgetIdRef.current = window.turnstile.render("#turnstile-container", {
      sitekey: turnstileSiteKey,
      callback: (token: string) => {
        setTurnstileToken(token)
        setError("")
      },
      "expired-callback": () => setTurnstileToken(""),
      "error-callback": () => {
        setTurnstileToken("")
        setError("Turnstile verification failed. Please retry the challenge.")
      },
    })
  }, [turnstileScriptLoaded, turnstileSiteKey])

  useEffect(() => {
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

  const resetResults = () => {
    pollingRef.current?.abort()
    pollingRef.current = null
    setVirusTotalResult(null)
    setUrlscanSubmit(null)
    setUrlscanResult(null)
    setUrlscanStatus("")
    setVirusTotalError("")
    setLiveScanError("")
    setScreenshotRefreshKey(0)
    setScreenshotLoading(false)
    setScreenshotError(false)
  }

  const pollUrlscanResult = async (uuid: string) => {
    pollingRef.current?.abort()
    const controller = new AbortController()
    pollingRef.current = controller

    const maxAttempts = 60
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (controller.signal.aborted) return

      try {
        const response = await fetch(`/api/urlscan/result/${encodeURIComponent(uuid)}`, {
          method: "GET",
          signal: controller.signal,
          headers: {
            Accept: "application/json",
          },
        })

        if (response.ok) {
          const data = await response.json()
          setUrlscanResult(data)
          setUrlscanStatus("Complete")
          return
        }

        // 404 is common while urlscan is processing
        if (response.status !== 404) {
          const data = await response.json().catch(() => ({}))
          throw new Error(data?.error || "Failed to fetch live scan result")
        }

        setUrlscanStatus(`Processing… (${attempt + 1}/${maxAttempts})`)
      } catch (err) {
        if (controller.signal.aborted) return
        throw err
      }

      await new Promise((resolve) => setTimeout(resolve, 2000))
    }

    throw new Error("Live scan is taking longer than usual. Please try again in a moment.")
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

    if (!turnstileToken) {
      setError("Please complete the Turnstile verification before scanning.")
      return
    }

    setLoading(true)
    setError("")
    resetResults()

    try {
      const normalizedUrl = normalizeUrl(url)

      setUrlscanStatus("Submitting…")
      const response = await fetch("/api/scan/combined", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: normalizedUrl,
          visibility: urlscanVisibility,
          turnstileToken,
        }),
      })

      const data = (await response.json()) as CombinedScanResponse

      if (!response.ok) {
        throw new Error(data.error || "Scan failed")
      }

      if (data.virusTotal) {
        setVirusTotalResult(data.virusTotal)
      }
      if (data.virusTotalError) {
        setVirusTotalError(data.virusTotalError)
      }

      if (data.liveSubmit) {
        setUrlscanSubmit(data.liveSubmit)
        if (data.liveSubmit.uuid) {
          setUrlscanStatus("Queued")
          setScreenshotError(false)
          setScreenshotLoading(true)
          setScreenshotRefreshKey((v) => v + 1)
          try {
            await pollUrlscanResult(data.liveSubmit.uuid)
          } catch (pollErr) {
            setLiveScanError(
              pollErr instanceof Error ? pollErr.message : "Failed to fetch live scan result",
            )
            setUrlscanStatus("Timed out")
          }
        } else {
          setLiveScanError("Live scan did not return a uuid")
          setUrlscanStatus("")
        }
      } else {
        if (data.liveError) setLiveScanError(data.liveError)
        setUrlscanStatus("")
      }

      if (!data.virusTotal && !data.liveSubmit) {
        setError("Both scans failed. Please try again.")
      }
    } catch (err) {
      // Keep global errors for the initial combined request only.
      setError(err instanceof Error ? err.message : "An unexpected error occurred")
    } finally {
      setLoading(false)
      setTurnstileToken("")
      if (window.turnstile && widgetIdRef.current) {
        window.turnstile.reset(widgetIdRef.current)
      }
    }
  }

  useEffect(() => {
    return () => {
      pollingRef.current?.abort()
    }
  }, [])

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

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-blue-900 dark:to-indigo-900 transition-all duration-500">
      <Script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        strategy="afterInteractive"
        onLoad={() => setTurnstileScriptLoaded(true)}
      />
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto">
          {/* Theme Toggle */}
          <div className="flex justify-end items-center gap-2 mb-4">
            <a
              href="https://buymeacoffee.com/debasisbiswas"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center rounded-full bg-pink-100 dark:bg-pink-200 hover:bg-pink-200 dark:hover:bg-pink-300 text-pink-600 dark:text-pink-700 shadow transition-colors duration-200 w-8 h-8 focus:outline-none focus:ring-2 focus:ring-pink-300"
              title="Sponsor on Buy Me a Coffee"
              aria-label="Sponsor on Buy Me a Coffee"
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 20 20"
                fill="currentColor"
                className="h-4 w-4"
              >
                <path d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z" />
              </svg>
            </a>
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
              Analyze URLs for potential phishing threats and preview how a site renders.
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
                    {loading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4" />
                    )}
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>

                <div className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 bg-white/60 dark:bg-gray-900/40 px-3 py-2">
                  <div className="space-y-0.5">
                    <Label className="text-sm text-gray-900 dark:text-gray-100">
                      Live Scan Visibility
                    </Label>
                    <p className="text-xs text-gray-600 dark:text-gray-400">
                      Toggle private live scan.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-600 dark:text-gray-400">Public</span>
                    <Switch
                      checked={urlscanVisibility === "private"}
                      onCheckedChange={(checked) =>
                        setUrlscanVisibility(checked ? "private" : "public")
                      }
                      disabled={loading}
                    />
                    <span className="text-xs text-gray-600 dark:text-gray-400">Private</span>
                  </div>
                </div>

                <div className="flex justify-center">
                  <div id="turnstile-container" className="min-h-[65px]" />
                </div>
              </form>

              {error && (
                <Alert className="mt-4 border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/50 animate-scale-in">
                  <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                  <AlertDescription className="text-red-800 dark:text-red-200">
                    {error}
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {loading && (
            <Card className="mb-6 animate-fade-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Scanning in progress
                </CardTitle>
                <CardDescription className="text-gray-600 dark:text-gray-400">
                  Running multiple checks and gathering metadata…
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                    <Skeleton className="h-3 w-24" />
                    <Skeleton className="mt-2 h-4 w-5/6" />
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                    <Skeleton className="h-3 w-28" />
                    <Skeleton className="mt-2 h-4 w-2/3" />
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                  <Skeleton className="h-3 w-32" />
                  <Skeleton className="mt-2 h-4 w-full" />
                  <Skeleton className="mt-2 h-4 w-11/12" />
                </div>
              </CardContent>
            </Card>
          )}

          {/* Results */}
          {(virusTotalResult || virusTotalError) && (
            <div className="space-y-6 animate-fade-in">
              {virusTotalError && (
                <Alert className="border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/50 animate-scale-in">
                  <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                  <AlertDescription className="text-red-800 dark:text-red-200">
                    {virusTotalError}
                  </AlertDescription>
                </Alert>
              )}
              {/* Main Results Card */}
              {virusTotalResult && (
                <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                      {getThreatIcon(virusTotalResult.threatLevel)}
                      Scan Results
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          URL
                        </label>
                        <p className="text-sm break-all font-mono text-gray-900 dark:text-gray-100">
                          {virusTotalResult.url}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Threat Level
                        </label>
                        <p
                          className={`text-sm font-semibold capitalize ${getThreatColor(virusTotalResult.threatLevel)}`}
                        >
                          {virusTotalResult.threatLevel}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Detection Ratio
                        </label>
                        <p className="text-sm text-gray-900 dark:text-gray-100">
                          <span className="font-bold text-lg">{virusTotalResult.positives}</span> /{" "}
                          {virusTotalResult.total} engines detected threats
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Scan Date
                        </label>
                        <p className="text-sm text-gray-900 dark:text-gray-100">
                          {virusTotalResult.scanDate}
                        </p>
                      </div>
                    </div>

                    {virusTotalResult.details && (
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Details
                        </label>
                        <p className="text-sm text-gray-700 dark:text-gray-300">
                          {virusTotalResult.details}
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* RDAP Information */}
              {virusTotalResult?.rdap && (
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
                        { label: "Domain", value: virusTotalResult.rdap.domain },
                        { label: "Registrar", value: virusTotalResult.rdap.registrar },
                        { label: "Organization", value: virusTotalResult.rdap.organization },
                        { label: "Country", value: virusTotalResult.rdap.country },
                        { label: "Creation Date", value: virusTotalResult.rdap.creation_date },
                        { label: "Expiration Date", value: virusTotalResult.rdap.expiration_date },
                      ].map((item, index) => (
                        <div
                          key={index}
                          className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200"
                        >
                          <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                            {item.label}
                          </label>
                          <p className="text-sm text-gray-900 dark:text-gray-100">{item.value}</p>
                        </div>
                      ))}
                    </div>

                    {virusTotalResult.rdap.name_servers &&
                      virusTotalResult.rdap.name_servers.length > 0 && (
                        <div className="mt-4">
                          <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                            Name Servers
                          </label>
                          <div className="mt-2 space-y-2">
                            {virusTotalResult.rdap.name_servers.map((ns, index) => (
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

                    {virusTotalResult.rdap.status && virusTotalResult.rdap.status.length > 0 && (
                      <div className="mt-4">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Domain Status
                        </label>
                        <div className="mt-2 space-y-2">
                          {virusTotalResult.rdap.status.map((status, index) => (
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
              {virusTotalResult?.scans && Object.keys(virusTotalResult.scans).length > 0 && (
                <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                      <Search className="h-5 w-5" />
                      Detailed Scan Results ({Object.keys(virusTotalResult.scans).length} Engines)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {Object.entries(virusTotalResult.scans).map(([engine, scan]) => (
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
                            <span className="font-medium text-sm text-gray-900 dark:text-gray-100">
                              {engine}
                            </span>
                          </div>
                          <div className="text-right">
                            {scan.detected ? (
                              <span className="text-red-600 dark:text-red-400 text-sm font-medium">
                                {scan.result}
                              </span>
                            ) : (
                              <span className="text-green-600 dark:text-green-400 text-sm font-medium">
                                Clean
                              </span>
                            )}
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              v{scan.version}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {(urlscanSubmit || urlscanStatus || liveScanError) && (
            <div className="space-y-6 animate-fade-in">
              <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                      <Shield className="h-5 w-5" />
                      Live Scan Results
                    </CardTitle>
                    {(urlscanStatus || liveScanError) && (
                      <Badge
                        variant={statusBadgeVariant(liveScanError ? "Error" : urlscanStatus || "—")}
                        className={
                          !liveScanError &&
                          urlscanStatus &&
                          !urlscanStatus.toLowerCase().includes("complete")
                            ? "animate-pulse"
                            : ""
                        }
                      >
                        {liveScanError ? "Error" : urlscanStatus || "—"}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {liveScanError && (
                    <Alert className="border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/50 animate-scale-in">
                      <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                      <AlertDescription className="text-red-800 dark:text-red-200">
                        {liveScanError}
                      </AlertDescription>
                    </Alert>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                        Status
                      </label>
                      <div className="mt-1 flex items-center gap-2">
                        {!urlscanResult && urlscanSubmit?.uuid && !liveScanError && (
                          <Loader2 className="h-4 w-4 animate-spin text-gray-500 dark:text-gray-300" />
                        )}
                        <p className="text-sm text-gray-900 dark:text-gray-100">
                          {urlscanStatus || "—"}
                        </p>
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                      <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                        Visibility
                      </label>
                      <p className="text-sm text-gray-900 dark:text-gray-100 capitalize">
                        {urlscanVisibility}
                      </p>
                    </div>
                  </div>

                  {urlscanResult && (
                    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white/60 dark:bg-gray-900/40 p-4 space-y-4">
                      {(() => {
                        const stats = urlscanResult?.stats
                        const uniqIps =
                          typeof stats?.uniqIPs === "number" ? stats.uniqIPs : undefined
                        const uniqCountries =
                          typeof stats?.uniqCountries === "number" ? stats.uniqCountries : undefined
                        const uniqDomains =
                          typeof stats?.uniqDomains === "number" ? stats.uniqDomains : undefined
                        const requests =
                          typeof stats?.requests === "number" ? stats.requests : undefined

                        const ip = toOptionalText(urlscanResult?.page?.ip)
                        const country = toOptionalText(urlscanResult?.page?.country)
                        const asnName = toOptionalText(urlscanResult?.page?.asnname)
                        const asn = toOptionalText(urlscanResult?.page?.asn)
                        const domain = toOptionalText(urlscanResult?.page?.domain)
                        const submittedUrl = toOptionalText(urlscanResult?.task?.url)
                        const effectiveUrl = toOptionalText(urlscanResult?.page?.url)
                        const pageTitle = toOptionalText(urlscanResult?.page?.title)
                        const time = toOptionalText(urlscanResult?.task?.time)
                        const scannerCountry = toOptionalText(urlscanResult?.page?.country)
                        const submitterCountry = toOptionalText(urlscanResult?.task?.country)

                        const verdicts =
                          isRecord(urlscanResult) && isRecord(urlscanResult["verdicts"])
                            ? (urlscanResult["verdicts"] as Record<string, unknown>)
                            : null
                        const overallVerdict =
                          verdicts && isRecord(verdicts["overall"])
                            ? (verdicts["overall"] as Record<string, unknown>)
                            : verdicts && isRecord(verdicts["urlscan"])
                              ? (verdicts["urlscan"] as Record<string, unknown>)
                              : null
                        const malicious = overallVerdict ? overallVerdict["malicious"] : undefined
                        const categoriesValue = overallVerdict
                          ? overallVerdict["categories"]
                          : undefined
                        const categories = Array.isArray(categoriesValue)
                          ? categoriesValue.filter(
                              (c): c is string => typeof c === "string" && c.trim().length > 0,
                            )
                          : []
                        const verdictText =
                          malicious === true
                            ? "Malicious"
                            : categories.length > 0
                              ? categories[0]
                              : "No classification"

                        const summaryBits: string[] = []
                        if (
                          typeof uniqIps === "number" &&
                          typeof uniqCountries === "number" &&
                          typeof uniqDomains === "number" &&
                          typeof requests === "number"
                        ) {
                          summaryBits.push(
                            `This website contacted ${uniqIps} IPs in ${uniqCountries} countries across ${uniqDomains} domains to perform ${requests} HTTP transactions.`,
                          )
                        }
                        if (ip) {
                          const location = country ? `, located in ${country}` : ""
                          const owner = asnName
                            ? ` and belongs to ${asnName}`
                            : asn
                              ? ` and belongs to ${asn}`
                              : ""
                          summaryBits.push(`The main IP is ${ip}${location}${owner}.`)
                        }
                        if (domain) {
                          summaryBits.push(`The main domain is ${domain}.`)
                        }

                        const liveRows: Array<{ label: string; value: string }> = []
                        liveRows.push({ label: "Verdict", value: verdictText })
                        if (submittedUrl)
                          liveRows.push({ label: "Submitted URL", value: submittedUrl })
                        if (effectiveUrl)
                          liveRows.push({ label: "Effective URL", value: effectiveUrl })
                        if (time || submitterCountry || scannerCountry) {
                          const parts = [
                            time ? `On ${time}` : null,
                            submitterCountry ? `from ${submitterCountry}` : null,
                            scannerCountry ? `scanned in ${scannerCountry}` : null,
                          ].filter(Boolean) as string[]
                          if (parts.length)
                            liveRows.push({ label: "Submission", value: parts.join(" ") })
                        }
                        if (pageTitle) liveRows.push({ label: "Page Title", value: pageTitle })
                        if (domain) liveRows.push({ label: "Domain", value: domain })
                        if (ip) {
                          const aRecord = asn
                            ? `${ip} (${asn}${asnName ? ` • ${asnName}` : ""})`
                            : asnName
                              ? `${ip} (${asnName})`
                              : ip
                          liveRows.push({ label: "Current DNS A record", value: aRecord })
                        }

                        return (
                          <>
                            {summaryBits.length > 0 && (
                              <div>
                                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                  Summary
                                </p>
                                <p className="mt-2 text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                                  {summaryBits.join(" ")}
                                </p>
                              </div>
                            )}

                            <div>
                              <div className="flex items-center justify-between gap-3">
                                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                  Live information
                                </p>
                                <Badge
                                  variant={scoreBadgeVariant(
                                    overallVerdict?.score,
                                    overallVerdict?.malicious,
                                  )}
                                >
                                  {verdictText}
                                </Badge>
                              </div>
                              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                                {liveRows
                                  .filter(
                                    (r) => typeof r.value === "string" && r.value.trim().length > 0,
                                  )
                                  .slice(0, 8)
                                  .map((row) => (
                                    <div
                                      key={row.label}
                                      className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600"
                                    >
                                      <p className="text-xs text-gray-500 dark:text-gray-400">
                                        {row.label}
                                      </p>
                                      <p
                                        className={
                                          row.label.toLowerCase().includes("url")
                                            ? "mt-1 text-sm break-all font-mono text-gray-900 dark:text-gray-100"
                                            : "mt-1 text-sm text-gray-900 dark:text-gray-100"
                                        }
                                      >
                                        {row.value}
                                      </p>
                                    </div>
                                  ))}
                              </div>
                            </div>
                          </>
                        )
                      })()}
                    </div>
                  )}

                  {urlscanSubmit?.uuid &&
                    !urlscanResult &&
                    !liveScanError &&
                    urlscanStatus !== "Timed out" && (
                      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white/60 dark:bg-gray-900/40 p-4">
                        <div className="flex items-center justify-between gap-3 mb-3">
                          <div className="space-y-1">
                            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                              Fetching details…
                            </p>
                            <p className="text-xs text-gray-600 dark:text-gray-400">
                              This usually finishes in a few seconds.
                            </p>
                          </div>
                          <Badge variant="outline" className="font-mono">
                            {urlscanVisibility}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                            <Skeleton className="h-3 w-24" />
                            <Skeleton className="mt-2 h-4 w-5/6" />
                          </div>
                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                            <Skeleton className="h-3 w-28" />
                            <Skeleton className="mt-2 h-4 w-2/3" />
                          </div>
                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                            <Skeleton className="h-3 w-20" />
                            <Skeleton className="mt-2 h-4 w-1/2" />
                          </div>
                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                            <Skeleton className="h-3 w-24" />
                            <Skeleton className="mt-2 h-4 w-1/3" />
                          </div>
                        </div>
                      </div>
                    )}

                  {urlscanResult && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Scanned URL
                        </label>
                        <p className="text-sm break-all font-mono text-gray-900 dark:text-gray-100">
                          {urlscanResult?.page?.url || url}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Domain
                        </label>
                        <p className="text-sm text-gray-900 dark:text-gray-100">
                          {urlscanResult?.page?.domain || "—"}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          IP
                        </label>
                        <p className="text-sm font-mono text-gray-900 dark:text-gray-100">
                          {urlscanResult?.page?.ip || "—"}
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors duration-200">
                        <label className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Country
                        </label>
                        <p className="text-sm text-gray-900 dark:text-gray-100">
                          {urlscanResult?.page?.country || "—"}
                        </p>
                      </div>
                    </div>
                  )}

                  {urlscanResult && (
                    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white/60 dark:bg-gray-900/40 p-4">
                      {(() => {
                        const verdicts =
                          isRecord(urlscanResult) && isRecord(urlscanResult["verdicts"])
                            ? (urlscanResult["verdicts"] as Record<string, unknown>)
                            : null
                        const verdictEntries = verdicts
                          ? Object.entries(verdicts)
                              .filter(([, v]) => {
                                if (!isRecord(v)) return false
                                const score = v["score"]
                                const malicious = v["malicious"]
                                return typeof score === "number" || typeof malicious === "boolean"
                              })
                              .slice(0, 8)
                          : []

                        const apps =
                          urlscanResult?.meta?.processors?.wappalyzer?.data?.applications ||
                          urlscanResult?.meta?.processors?.wappa?.data?.applications ||
                          urlscanResult?.meta?.processors?.wappalyzer?.data?.technologies ||
                          urlscanResult?.meta?.processors?.wappa?.data?.technologies ||
                          []
                        const names: string[] = Array.isArray(apps)
                          ? apps
                              .map((app) => {
                                if (typeof app === "string") return app
                                if (isRecord(app) && typeof app["name"] === "string") {
                                  return app["name"]
                                }
                                return null
                              })
                              .filter(
                                (name): name is string =>
                                  typeof name === "string" && name.trim().length > 0,
                              )
                          : []
                        const techDeduped = Array.from(new Set(names)).slice(0, 30)
                        const server = toOptionalText(urlscanResult?.page?.server)
                        const asn = toOptionalText(urlscanResult?.page?.asn)
                        const hasTech = techDeduped.length > 0 || !!server || !!asn

                        const requests = Array.isArray(urlscanResult?.data?.requests)
                          ? urlscanResult.data.requests
                          : []
                        const requestRows = requests.slice(0, 20)
                        const hasRequests = requestRows.length > 0

                        const lists = urlscanResult?.lists
                        const domains = asStringArray(lists?.domains).slice(0, 30)
                        const ips = asStringArray(lists?.ips).slice(0, 30)
                        const urls = asStringArray(lists?.urls).slice(0, 30)
                        const links = asStringArray(urlscanResult?.data?.links).slice(0, 30)
                        const hasIndicators =
                          domains.length || ips.length || urls.length || links.length

                        const showAccordion =
                          verdictEntries.length > 0 || hasTech || hasRequests || hasIndicators
                        if (!showAccordion) return null

                        return (
                          <Accordion type="multiple" className="w-full">
                            {verdictEntries.length > 0 && (
                              <AccordionItem value="verdicts">
                                <AccordionTrigger className="text-gray-900 dark:text-gray-100">
                                  Verdicts
                                </AccordionTrigger>
                                <AccordionContent>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {verdictEntries.map(([name, v]) => {
                                      const verdict = isRecord(v) ? v : null
                                      const score = verdict?.["score"]
                                      const maliciousFlag = verdict?.["malicious"]
                                      const categoriesValue = verdict?.["categories"]
                                      const categoryList = Array.isArray(categoriesValue)
                                        ? categoriesValue.filter(
                                            (c): c is string =>
                                              typeof c === "string" && c.trim().length > 0,
                                          )
                                        : []

                                      return (
                                        <div
                                          key={name}
                                          className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600"
                                        >
                                          <div className="flex items-center justify-between gap-2">
                                            <p className="text-sm font-medium text-gray-900 dark:text-gray-100 capitalize">
                                              {name.replace(/_/g, " ")}
                                            </p>
                                            <Badge
                                              variant={scoreBadgeVariant(score, maliciousFlag)}
                                            >
                                              {maliciousFlag === true ? "Malicious" : "OK"}
                                            </Badge>
                                          </div>
                                          <div className="mt-2 grid grid-cols-2 gap-2">
                                            {typeof score !== "undefined" && (
                                              <div>
                                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                                  Score
                                                </p>
                                                <p className="text-sm text-gray-900 dark:text-gray-100">
                                                  {toText(score)}
                                                </p>
                                              </div>
                                            )}
                                            {categoryList.length > 0 && (
                                              <div>
                                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                                  Categories
                                                </p>
                                                <p className="text-sm text-gray-900 dark:text-gray-100">
                                                  {categoryList.slice(0, 3).join(", ")}
                                                </p>
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      )
                                    })}
                                  </div>
                                </AccordionContent>
                              </AccordionItem>
                            )}

                            {hasTech && (
                              <AccordionItem value="technologies">
                                <AccordionTrigger className="text-gray-900 dark:text-gray-100">
                                  Technologies
                                </AccordionTrigger>
                                <AccordionContent>
                                  <div className="space-y-3">
                                    {(server || asn) && (
                                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        {server && (
                                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                              Server
                                            </p>
                                            <p className="text-sm text-gray-900 dark:text-gray-100">
                                              {server}
                                            </p>
                                          </div>
                                        )}
                                        {asn && (
                                          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                              ASN
                                            </p>
                                            <p className="text-sm text-gray-900 dark:text-gray-100">
                                              {asn}
                                            </p>
                                          </div>
                                        )}
                                      </div>
                                    )}

                                    {techDeduped.length > 0 && (
                                      <div className="flex flex-wrap gap-2">
                                        {techDeduped.map((t) => (
                                          <Badge
                                            key={t}
                                            variant="secondary"
                                            className="bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                                          >
                                            {t}
                                          </Badge>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </AccordionContent>
                              </AccordionItem>
                            )}

                            {hasRequests && (
                              <AccordionItem value="requests">
                                <AccordionTrigger className="text-gray-900 dark:text-gray-100">
                                  Network Requests ({requests.length})
                                </AccordionTrigger>
                                <AccordionContent>
                                  <ScrollArea className="h-80 rounded-md border border-gray-200 dark:border-gray-700">
                                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                                      {requestRows.map((entry: unknown, idx: number) => {
                                        const record = isRecord(entry) ? entry : null
                                        const requestInfo =
                                          record && isRecord(record["request"])
                                            ? (record["request"] as Record<string, unknown>)
                                            : null
                                        const responseInfo =
                                          record && isRecord(record["response"])
                                            ? (record["response"] as Record<string, unknown>)
                                            : null
                                        const method =
                                          asString(requestInfo?.["method"]) ||
                                          asString(record?.["method"])
                                        const reqUrl =
                                          asString(requestInfo?.["url"]) ||
                                          asString(record?.["url"])
                                        const status =
                                          responseInfo?.["status"] ?? record?.["status"]
                                        const mime =
                                          asString(responseInfo?.["mimeType"]) ||
                                          asString(responseInfo?.["type"])
                                        if (!reqUrl) return null
                                        return (
                                          <div
                                            key={idx}
                                            className="p-3 bg-white/70 dark:bg-gray-900/40"
                                          >
                                            <div className="flex items-center justify-between gap-2">
                                              <div className="flex items-center gap-2">
                                                {method && (
                                                  <Badge variant="outline" className="font-mono">
                                                    {toText(method)}
                                                  </Badge>
                                                )}
                                                {typeof status !== "undefined" && (
                                                  <Badge
                                                    variant={
                                                      typeof status === "number" && status >= 400
                                                        ? "destructive"
                                                        : "secondary"
                                                    }
                                                    className="font-mono"
                                                  >
                                                    {toText(status)}
                                                  </Badge>
                                                )}
                                              </div>
                                              {mime && (
                                                <span className="text-xs text-gray-500 dark:text-gray-400">
                                                  {toText(mime)}
                                                </span>
                                              )}
                                            </div>
                                            <p className="mt-2 text-sm break-all font-mono text-gray-900 dark:text-gray-100">
                                              {toText(reqUrl)}
                                            </p>
                                          </div>
                                        )
                                      })}
                                    </div>
                                  </ScrollArea>
                                </AccordionContent>
                              </AccordionItem>
                            )}

                            {hasIndicators ? (
                              <AccordionItem value="indicators">
                                <AccordionTrigger className="text-gray-900 dark:text-gray-100">
                                  Extracted Indicators
                                </AccordionTrigger>
                                <AccordionContent>
                                  <div className="space-y-4">
                                    {domains.length > 0 && (
                                      <div>
                                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                                          Domains
                                        </p>
                                        <div className="flex flex-wrap gap-2">
                                          {domains.map((d) => (
                                            <Badge key={d} variant="outline" className="font-mono">
                                              {d}
                                            </Badge>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {ips.length > 0 && (
                                      <div>
                                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                                          IPs
                                        </p>
                                        <div className="flex flex-wrap gap-2">
                                          {ips.map((ipVal) => (
                                            <Badge
                                              key={ipVal}
                                              variant="outline"
                                              className="font-mono"
                                            >
                                              {ipVal}
                                            </Badge>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {urls.length > 0 && (
                                      <div>
                                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                                          URLs
                                        </p>
                                        <ScrollArea className="h-48 rounded-md border border-gray-200 dark:border-gray-700">
                                          <div className="p-3 space-y-2">
                                            {urls.map((u) => (
                                              <p
                                                key={u}
                                                className="text-xs break-all font-mono text-gray-900 dark:text-gray-100"
                                              >
                                                {u}
                                              </p>
                                            ))}
                                          </div>
                                        </ScrollArea>
                                      </div>
                                    )}

                                    {links.length > 0 && (
                                      <div>
                                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                                          Links
                                        </p>
                                        <ScrollArea className="h-48 rounded-md border border-gray-200 dark:border-gray-700">
                                          <div className="p-3 space-y-2">
                                            {links.map((u) => (
                                              <p
                                                key={u}
                                                className="text-xs break-all font-mono text-gray-900 dark:text-gray-100"
                                              >
                                                {u}
                                              </p>
                                            ))}
                                          </div>
                                        </ScrollArea>
                                      </div>
                                    )}
                                  </div>
                                </AccordionContent>
                              </AccordionItem>
                            ) : null}
                          </Accordion>
                        )
                      })()}
                    </div>
                  )}
                </CardContent>
              </Card>

              {urlscanSubmit?.uuid && (
                <Card className="hover-lift animate-scale-in glass-effect bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-gray-200 dark:border-gray-700">
                  <CardHeader>
                    <div className="flex items-center justify-between gap-3">
                      <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-gray-100">
                        <Globe className="h-5 w-5" />
                        Live Screenshot Preview
                      </CardTitle>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setScreenshotError(false)
                          setScreenshotLoading(true)
                          setScreenshotRefreshKey((v) => v + 1)
                        }}
                      >
                        Refresh
                      </Button>
                    </div>
                    <CardDescription className="text-gray-600 dark:text-gray-400">
                      Screenshot may take a few seconds to appear.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
                      <AspectRatio ratio={16 / 9}>
                        <div className="relative h-full w-full">
                          <div className="absolute inset-0">
                            <Skeleton className="h-full w-full rounded-none" />
                          </div>

                          {(screenshotLoading || screenshotError) && (
                            <div className="absolute inset-0 flex items-center justify-center bg-white/70 dark:bg-gray-900/60">
                              {screenshotLoading ? (
                                <div className="flex items-center gap-2 text-gray-700 dark:text-gray-200">
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                  <span className="text-sm">Loading preview…</span>
                                </div>
                              ) : (
                                <div className="text-center px-6">
                                  <p className="text-sm text-gray-900 dark:text-gray-100 font-medium">
                                    Preview unavailable
                                  </p>
                                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                                    Try refreshing in a few seconds.
                                  </p>
                                </div>
                              )}
                            </div>
                          )}

                          <Image
                            key={screenshotRefreshKey}
                            src={`/api/urlscan/screenshot/${encodeURIComponent(urlscanSubmit.uuid)}?t=${screenshotRefreshKey}`}
                            alt="Live scan screenshot"
                            fill
                            sizes="100vw"
                            unoptimized
                            className={`object-cover relative transition-opacity duration-300 ${
                              screenshotLoading || screenshotError ? "opacity-0" : "opacity-100"
                            }`}
                            loading="lazy"
                            onLoad={() => {
                              setScreenshotLoading(false)
                              setScreenshotError(false)
                            }}
                            onError={() => {
                              setScreenshotLoading(false)
                              setScreenshotError(true)
                            }}
                          />
                        </div>
                      </AspectRatio>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Footer */}
          <footer className="mt-12 pt-8 border-t border-gray-200 dark:border-gray-700 animate-fade-in space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-left max-w-2xl mx-auto">
              <div className="space-y-2.5">
                <div className="flex items-center gap-2 text-gray-900 dark:text-gray-100 font-semibold text-sm">
                  <Shield className="h-4 w-4 text-blue-600 dark:text-blue-400 animate-pulse" />
                  <span>Phishing URL Scanner</span>
                </div>
                <p className="text-xs text-gray-650 dark:text-gray-450 leading-relaxed">
                  A high-fidelity security scanner designed to inspect domains, detect suspicious
                  redirects, and identify potential threat vectors. Please browse responsibly.
                </p>
              </div>

              <div className="space-y-2.5 md:text-right md:flex md:flex-col md:items-end">
                <div className="text-gray-900 dark:text-gray-100 font-semibold text-sm">
                  Resources & Support
                </div>
                <div className="flex flex-wrap gap-x-3 gap-y-2 text-xs">
                  <a
                    href="/privacy-policy"
                    className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline underline-offset-2 transition-colors duration-200"
                  >
                    Privacy Policy
                  </a>
                  <span className="text-gray-300 dark:text-gray-700 hidden md:inline">|</span>
                  <a
                    href="mailto:contact@debasisbiswas.in"
                    className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline underline-offset-2 transition-colors duration-200"
                  >
                    Support & Contact
                  </a>
                  <span className="text-gray-300 dark:text-gray-700 hidden md:inline">|</span>
                  <a
                    href="https://buymeacoffee.com/debasisbiswas"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-pink-600 dark:text-pink-400 hover:text-pink-800 dark:hover:text-pink-300 underline underline-offset-2 transition-colors duration-200"
                  >
                    Sponsor
                  </a>
                </div>
                <p className="text-[11px] text-gray-500 dark:text-gray-405">
                  Made by Debasis Biswas • contact@debasisbiswas.in
                </p>
              </div>
            </div>
            <div className="text-center pt-4 border-t border-gray-100 dark:border-gray-800/50 text-[11px] text-gray-400 dark:text-gray-500">
              © {new Date().getFullYear()} Phishing URL Scanner. All rights reserved.
            </div>
          </footer>
        </div>
      </div>
    </div>
  )
}
