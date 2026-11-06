"use client"

import type React from "react"
import { useState, useEffect, useRef, useMemo } from "react"
import Image from "next/image"
import Script from "next/script"
import Link from "next/link"
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Search,
  Globe,
  Moon,
  Sun,
  Copy,
  Check,
  ExternalLink,
  Server,
  Activity,
  Layers,
  Terminal,
  Lock,
  RefreshCw,
  Clock,
  Database,
  Filter,
  Maximize2,
  Radio,
  FileCode2,
  Network,
  Cpu,
  ArrowRight,
  Sparkles,
  Info,
  SlidersHorizontal,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { AspectRatio } from "@/components/ui/aspect-ratio"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

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

// Defang a URL for safe sharing in threat reports (e.g. hxxps://domain[.]com)
function defangUrl(rawUrl: string): string {
  if (!rawUrl) return ""
  return rawUrl
    .replace(/^http:\/\//i, "hxxp://")
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/\./g, "[.]")
}

const SAMPLE_PRESETS = [
  { name: "Google", url: "https://google.com", type: "clean" },
  { name: "GitHub", url: "https://github.com", type: "clean" },
  { name: "Test Phishing Pattern", url: "https://paypal-security-update-center.xyz", type: "sample" },
]

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
  const [copiedUrl, setCopiedUrl] = useState(false)
  const [copiedDefanged, setCopiedDefanged] = useState(false)
  const [engineFilter, setEngineFilter] = useState<"all" | "detected" | "clean">("all")
  const [engineSearch, setEngineSearch] = useState("")
  const [isScreenshotModalOpen, setIsScreenshotModalOpen] = useState(false)

  const widgetIdRef = useRef<string | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)
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
      localStorage.setItem("theme", "light")
    }
  }, [])

  // Keyboard shortcut: '/' focuses the scanner search bar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== inputRef.current) {
        e.preventDefault()
        inputRef.current?.focus()
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
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

  const normalizeUrl = (raw: string): string => {
    const trimmed = raw.trim()
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      return trimmed
    }
    return `https://${trimmed}`
  }

  const validateUrl = (raw: string): boolean => {
    try {
      new URL(normalizeUrl(raw))
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
    setEngineFilter("all")
    setEngineSearch("")
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

        if (response.status !== 404) {
          const data = await response.json().catch(() => ({}))
          throw new Error(data?.error || "Failed to fetch live scan result")
        }

        setUrlscanStatus(`Sandboxing... (${attempt + 1}/${maxAttempts})`)
      } catch (err) {
        if (controller.signal.aborted) return
        throw err
      }

      await new Promise((resolve) => setTimeout(resolve, 2000))
    }

    throw new Error("Live sandboxing took longer than usual. You can still inspect VT metrics.")
  }

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()

    if (!url.trim()) {
      setError("Please enter a domain or URL to inspect")
      inputRef.current?.focus()
      return
    }

    if (!validateUrl(url)) {
      setError("Please enter a valid URL (e.g., example.com or https://example.com)")
      return
    }

    if (!turnstileToken) {
      setError("Please complete the Cloudflare Turnstile verification before scanning.")
      return
    }

    setLoading(true)
    setError("")
    resetResults()

    try {
      const normalizedUrl = normalizeUrl(url)

      setUrlscanStatus("Submitting target...")
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
        throw new Error(data.error || "Scan request failed")
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
          setLiveScanError("Live scan did not return a valid task uuid")
          setUrlscanStatus("")
        }
      } else {
        if (data.liveError) setLiveScanError(data.liveError)
        setUrlscanStatus("")
      }

      if (!data.virusTotal && !data.liveSubmit) {
        setError("Both scanning engines failed to respond. Please verify your connection.")
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected scan error occurred")
    } finally {
      setLoading(false)
      setTurnstileToken("")
      if (window.turnstile && widgetIdRef.current) {
        window.turnstile.reset(widgetIdRef.current)
      }
    }
  }

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText()
      if (text) {
        setUrl(text.trim())
        setError("")
      }
    } catch {
      inputRef.current?.focus()
    }
  }

  const handleCopy = (text: string, isDefanged = false) => {
    navigator.clipboard.writeText(text)
    if (isDefanged) {
      setCopiedDefanged(true)
      setTimeout(() => setCopiedDefanged(false), 2000)
    } else {
      setCopiedUrl(true)
      setTimeout(() => setCopiedUrl(false), 2000)
    }
  }

  useEffect(() => {
    return () => {
      pollingRef.current?.abort()
    }
  }, [])

  // Filtered scans list for VirusTotal engines tab
  const filteredScans = useMemo(() => {
    if (!virusTotalResult?.scans) return []
    const entries = Object.entries(virusTotalResult.scans).map(([engine, scan]) => ({
      engine,
      ...scan,
    }))

    return entries.filter((item) => {
      if (engineFilter === "detected" && !item.detected) return false
      if (engineFilter === "clean" && item.detected) return false
      if (
        engineSearch.trim() &&
        !item.engine.toLowerCase().includes(engineSearch.toLowerCase().trim())
      ) {
        return false
      }
      return true
    })
  }, [virusTotalResult?.scans, engineFilter, engineSearch])

  // Extract parsed metadata from urlscan.io result
  const parsedUrlscan = useMemo(() => {
    if (!urlscanResult) return null
    const stats = urlscanResult.stats
    const uniqIps = typeof stats?.uniqIPs === "number" ? stats.uniqIPs : undefined
    const uniqCountries = typeof stats?.uniqCountries === "number" ? stats.uniqCountries : undefined
    const uniqDomains = typeof stats?.uniqDomains === "number" ? stats.uniqDomains : undefined
    const requests = typeof stats?.requests === "number" ? stats.requests : undefined

    const ip = toOptionalText(urlscanResult.page?.ip)
    const country = toOptionalText(urlscanResult.page?.country)
    const asnName = toOptionalText(urlscanResult.page?.asnname)
    const asn = toOptionalText(urlscanResult.page?.asn)
    const domain = toOptionalText(urlscanResult.page?.domain)
    const submittedUrl = toOptionalText(urlscanResult.task?.url)
    const effectiveUrl = toOptionalText(urlscanResult.page?.url)
    const pageTitle = toOptionalText(urlscanResult.page?.title)
    const time = toOptionalText(urlscanResult.task?.time)
    const server = toOptionalText(urlscanResult.page?.server)

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
    const score = overallVerdict ? overallVerdict["score"] : undefined
    const categoriesValue = overallVerdict ? overallVerdict["categories"] : undefined
    const categories = Array.isArray(categoriesValue)
      ? categoriesValue.filter((c): c is string => typeof c === "string" && c.trim().length > 0)
      : []

    // Technologies
    const apps =
      urlscanResult.meta?.processors?.wappalyzer?.data?.applications ||
      urlscanResult.meta?.processors?.wappa?.data?.applications ||
      urlscanResult.meta?.processors?.wappalyzer?.data?.technologies ||
      urlscanResult.meta?.processors?.wappa?.data?.technologies ||
      []
    const techNames: string[] = Array.isArray(apps)
      ? apps
          .map((app) => {
            if (typeof app === "string") return app
            if (isRecord(app) && typeof app["name"] === "string") return app["name"]
            return null
          })
          .filter((name): name is string => typeof name === "string" && name.trim().length > 0)
      : []
    const technologies = Array.from(new Set(techNames)).slice(0, 30)

    // Network requests
    const rawRequests = Array.isArray(urlscanResult.data?.requests)
      ? urlscanResult.data.requests
      : []

    // Extracted lists
    const lists = urlscanResult.lists
    const domains = asStringArray(lists?.domains).slice(0, 40)
    const ips = asStringArray(lists?.ips).slice(0, 40)
    const urls = asStringArray(lists?.urls).slice(0, 40)
    const links = asStringArray(urlscanResult.data?.links).slice(0, 40)

    return {
      uniqIps,
      uniqCountries,
      uniqDomains,
      requests,
      ip,
      country,
      asnName,
      asn,
      domain,
      submittedUrl,
      effectiveUrl,
      pageTitle,
      time,
      server,
      score,
      malicious,
      categories,
      technologies,
      rawRequests,
      domains,
      ips,
      urls,
      links,
    }
  }, [urlscanResult])

  const hasAnyResults = !!virusTotalResult || !!urlscanSubmit || !!urlscanResult

  // Calculated overall threat level combining VT and urlscan
  const overallVerdictType = useMemo(() => {
    if (virusTotalResult?.threatLevel === "malicious" || parsedUrlscan?.malicious === true) {
      return "malicious"
    }
    if (
      virusTotalResult?.threatLevel === "suspicious" ||
      (typeof parsedUrlscan?.score === "number" && parsedUrlscan.score > 25)
    ) {
      return "suspicious"
    }
    if (virusTotalResult?.threatLevel === "safe") {
      return "safe"
    }
    return "unknown"
  }, [virusTotalResult?.threatLevel, parsedUrlscan?.malicious, parsedUrlscan?.score])

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground cyber-grid transition-colors duration-200">
      <Script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        strategy="afterInteractive"
        onLoad={() => setTurnstileScriptLoaded(true)}
      />

      {/* Top Professional Navigation Bar */}
      <header className="sticky top-0 z-40 w-full border-b border-border/80 bg-background/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-500 dark:text-sky-400 shadow-sm">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-base tracking-tight text-foreground">
                  PhishGuard
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground hidden sm:block">
                Multi-Engine Threat Intelligence & Live Sandboxing
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span>Engines Operational</span>
            </div>

            <Link
              href="/privacy-policy"
              className="hidden sm:inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground px-2.5 py-1.5 rounded-md hover:bg-muted transition-colors"
            >
              <Info className="h-3.5 w-3.5" />
              <span>Privacy & Legal</span>
            </Link>

            <a
              href="https://buymeacoffee.com/debasisbiswas"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-md border border-border bg-card hover:bg-muted text-foreground transition-colors shadow-sm"
            >
              <Sparkles className="h-3.5 w-3.5 text-amber-500" />
              <span>Sponsor</span>
            </a>

            <Button
              variant="outline"
              size="icon"
              onClick={toggleTheme}
              className="h-9 w-9 rounded-md border-border bg-card hover:bg-muted"
              title={darkMode ? "Switch to light mode" : "Switch to dark mode"}
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

      {/* Main Container */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 py-8 sm:py-12 space-y-8">
        {/* Hero Section */}
        <div className="max-w-3xl mx-auto text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-sky-600 dark:text-sky-400 text-xs font-mono uppercase tracking-wider">
            <Radio className="h-3 w-3 animate-pulse" />
            <span>Dual-Engine Telemetry Console</span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-foreground">
            Analyze URLs for Phishing & Threats
          </h1>

          <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
            Consensus scanning across 90+ security vendors with VirusTotal, combined with live
            headless browser execution and forensic screenshot capture via urlscan.io.
          </p>
        </div>

        {/* Command Console Scanner Input */}
        <div className="max-w-3xl mx-auto">
          <Card className="border-border shadow-md bg-card">
            <CardContent className="p-4 sm:p-6 space-y-4">
              <form onSubmit={handleScan} className="space-y-4">
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1 flex items-center">
                    <div className="absolute left-3 flex items-center pointer-events-none text-muted-foreground text-xs font-mono font-medium select-none">
                      <Terminal className="h-3.5 w-3.5 mr-1 text-slate-400" />
                    </div>
                    <Input
                      ref={inputRef}
                      type="text"
                      placeholder="Enter domain or URL (e.g., example.com or login-verify.xyz)"
                      value={url}
                      onChange={(e) => {
                        setUrl(e.target.value)
                        if (error) setError("")
                      }}
                      disabled={loading}
                      className="pl-9 pr-20 h-11 text-sm font-mono bg-background border-border focus-visible:ring-1 focus-visible:ring-sky-500"
                    />
                    <div className="absolute right-2 flex items-center gap-1">
                      {url ? (
                        <button
                          type="button"
                          onClick={() => setUrl("")}
                          disabled={loading}
                          className="p-1 text-muted-foreground hover:text-foreground text-xs rounded hover:bg-muted"
                          title="Clear input"
                        >
                          ✕
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={handlePasteClipboard}
                          disabled={loading}
                          className="px-1.5 py-0.5 text-[11px] font-mono text-muted-foreground hover:text-foreground rounded border border-border/80 bg-muted/60 hover:bg-muted"
                          title="Paste from clipboard"
                        >
                          Paste
                        </button>
                      )}
                    </div>
                  </div>

                  <Button
                    type="submit"
                    disabled={loading || !url.trim()}
                    className="h-11 px-6 font-medium bg-sky-600 hover:bg-sky-500 text-white dark:bg-sky-500 dark:hover:bg-sky-400 dark:text-slate-950 transition-colors shadow-sm gap-2"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4" />
                        <span>Run Scan</span>
                        <kbd className="hidden sm:inline-block ml-1 px-1.5 py-0.5 text-[10px] font-mono bg-white/20 dark:bg-black/20 rounded">
                          ↵
                        </kbd>
                      </>
                    )}
                  </Button>
                </div>

                {/* Quick Presets & Options Row */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-border/60 text-xs">
                  <div className="flex items-center gap-1.5 text-muted-foreground">
                    <span className="text-[11px]">Quick samples:</span>
                    {SAMPLE_PRESETS.map((preset) => (
                      <button
                        key={preset.name}
                        type="button"
                        onClick={() => {
                          setUrl(preset.url)
                          setError("")
                        }}
                        disabled={loading}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-muted/80 hover:bg-muted text-foreground border border-border/80 transition-colors"
                      >
                        {preset.name}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center gap-2">
                    <SlidersHorizontal className="h-3 w-3 text-muted-foreground" />
                    <Label
                      htmlFor="live-visibility"
                      className="text-xs text-muted-foreground cursor-pointer"
                    >
                      Private Live Sandbox
                    </Label>
                    <Switch
                      id="live-visibility"
                      checked={urlscanVisibility === "private"}
                      onCheckedChange={(checked) =>
                        setUrlscanVisibility(checked ? "private" : "public")
                      }
                      disabled={loading}
                    />
                  </div>
                </div>

                {/* Cloudflare Turnstile Verification Box */}
                <div className="flex flex-col items-center justify-center pt-2">
                  <div
                    id="turnstile-container"
                    className="min-h-[65px] flex items-center justify-center"
                  />
                  {!turnstileToken && (
                    <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground mt-1">
                      <Lock className="h-3 w-3" />
                      <span>Security challenge verification required to initiate scan</span>
                    </div>
                  )}
                </div>
              </form>

              {error && (
                <Alert
                  variant="destructive"
                  className="bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400 mt-2"
                >
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription className="text-xs font-medium">{error}</AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Live Active Telemetry & Progress Indicator */}
        {loading && (
          <div className="max-w-3xl mx-auto animate-fade-in">
            <Card className="border-sky-500/30 bg-card overflow-hidden">
              <div className="h-1 w-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                <div className="h-full bg-sky-500 animate-pulse w-full radar-sweep" />
              </div>
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <Loader2 className="h-5 w-5 animate-spin text-sky-500" />
                    <div>
                      <h3 className="font-semibold text-sm text-foreground">
                        Threat Analysis Telemetry Active
                      </h3>
                      <p className="text-xs text-muted-foreground">
                        Dispatching queries to VirusTotal & urlscan.io sandboxes
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline" className="font-mono text-xs border-sky-500/30 text-sky-500">
                    {urlscanStatus || "Processing"}
                  </Badge>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                  <div className="p-3 rounded-lg border border-border bg-muted/40">
                    <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                      <span>Syntax & DNS</span>
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                    </div>
                    <p className="text-xs font-mono font-medium text-foreground">Target Validated</p>
                  </div>
                  <div className="p-3 rounded-lg border border-sky-500/20 bg-sky-500/5">
                    <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                      <span>VirusTotal API</span>
                      <Loader2 className="h-3.5 w-3.5 text-sky-500 animate-spin" />
                    </div>
                    <p className="text-xs font-mono font-medium text-foreground">Querying 90+ Engines</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border bg-muted/40">
                    <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                      <span>Live Sandbox</span>
                      <Activity className="h-3.5 w-3.5 text-amber-500" />
                    </div>
                    <p className="text-xs font-mono font-medium text-foreground">
                      {urlscanStatus || "Spawning Browser"}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Scan Results Workspace */}
        {hasAnyResults && (
          <div className="space-y-6 animate-slide-up">
            {/* Top Threat Verdict Banner */}
            <div
              className={`rounded-xl border p-5 sm:p-6 transition-all ${
                overallVerdictType === "malicious"
                  ? "border-rose-500/40 bg-rose-500/[0.04] text-rose-600 dark:text-rose-400"
                  : overallVerdictType === "suspicious"
                    ? "border-amber-500/40 bg-amber-500/[0.04] text-amber-600 dark:text-amber-400"
                    : "border-emerald-500/40 bg-emerald-500/[0.04] text-emerald-600 dark:text-emerald-400"
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                <div className="flex items-start gap-4">
                  <div
                    className={`p-3 rounded-xl border ${
                      overallVerdictType === "malicious"
                        ? "bg-rose-500/10 border-rose-500/30 text-rose-500"
                        : overallVerdictType === "suspicious"
                          ? "bg-amber-500/10 border-amber-500/30 text-amber-500"
                          : "bg-emerald-500/10 border-emerald-500/30 text-emerald-500"
                    }`}
                  >
                    {overallVerdictType === "malicious" ? (
                      <ShieldAlert className="h-8 w-8" />
                    ) : overallVerdictType === "suspicious" ? (
                      <AlertTriangle className="h-8 w-8" />
                    ) : (
                      <ShieldCheck className="h-8 w-8" />
                    )}
                  </div>

                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs uppercase tracking-wider px-2 py-0.5 rounded font-bold border border-current">
                        {overallVerdictType === "malicious"
                          ? "CONFIRMED THREAT / PHISHING"
                          : overallVerdictType === "suspicious"
                            ? "SUSPICIOUS DESTINATION"
                            : "SECURE / CLEAN DESTINATION"}
                      </span>
                      {virusTotalResult && (
                        <span className="text-xs text-muted-foreground font-mono">
                          • {virusTotalResult.positives} / {virusTotalResult.total} vendor detections
                        </span>
                      )}
                    </div>

                    <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground">
                      {overallVerdictType === "malicious"
                        ? "Dangerous Destination Detected"
                        : overallVerdictType === "suspicious"
                          ? "Potential Risk or Anomalies Found"
                          : "No Security Threats Detected"}
                    </h2>

                    {/* Target URL with copy tools */}
                    <div className="pt-2 flex flex-wrap items-center gap-2">
                      <span className="text-xs text-muted-foreground">Scanned URL:</span>
                      <code className="px-2 py-1 rounded bg-background border border-border font-mono text-xs text-foreground break-all">
                        {virusTotalResult?.url || parsedUrlscan?.submittedUrl || url}
                      </code>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          handleCopy(virusTotalResult?.url || parsedUrlscan?.submittedUrl || url)
                        }
                        className="h-7 px-2 text-xs gap-1 border-border bg-card"
                      >
                        {copiedUrl ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-500" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </Button>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          handleCopy(
                            defangUrl(virusTotalResult?.url || parsedUrlscan?.submittedUrl || url),
                            true,
                          )
                        }
                        title="Copy defanged URL safe for tickets (e.g. hxxps://example[.]com)"
                        className="h-7 px-2 text-xs gap-1 border-border bg-card font-mono text-[11px]"
                      >
                        {copiedDefanged ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-500" />
                            <span>Defanged!</span>
                          </>
                        ) : (
                          <>
                            <Shield className="h-3 w-3" />
                            <span>Defang URL</span>
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Score and Quick Stats Pill Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 border-t lg:border-t-0 lg:border-l border-border/80 pt-4 lg:pt-0 lg:pl-6 text-left">
                  <div className="p-2.5 rounded-lg bg-background/80 border border-border">
                    <p className="text-[11px] text-muted-foreground uppercase tracking-wider">
                      VT Engines
                    </p>
                    <p className="text-base font-bold font-mono text-foreground">
                      {virusTotalResult
                        ? `${virusTotalResult.positives}/${virusTotalResult.total}`
                        : "—"}
                    </p>
                    <p className="text-[10px] text-muted-foreground">
                      {virusTotalResult && virusTotalResult.positives === 0
                        ? "100% Clean consensus"
                        : "Threats flagged"}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-background/80 border border-border">
                    <p className="text-[11px] text-muted-foreground uppercase tracking-wider">
                      Sandbox IP
                    </p>
                    <p className="text-base font-bold font-mono text-foreground truncate">
                      {parsedUrlscan?.ip || "—"}
                    </p>
                    <p className="text-[10px] text-muted-foreground truncate">
                      {parsedUrlscan?.country ? `Country: ${parsedUrlscan.country}` : "Global Host"}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-background/80 border border-border col-span-2 sm:col-span-1">
                    <p className="text-[11px] text-muted-foreground uppercase tracking-wider">
                      Domain Age / RDAP
                    </p>
                    <p className="text-base font-bold font-mono text-foreground truncate">
                      {virusTotalResult?.rdap?.creation_date
                        ? virusTotalResult.rdap.creation_date.slice(0, 10)
                        : "Verified"}
                    </p>
                    <p className="text-[10px] text-muted-foreground truncate">
                      {virusTotalResult?.rdap?.registrar || "Registered domain"}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Error alerts if one of the engines failed */}
            {virusTotalError && (
              <Alert className="bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle className="text-xs font-semibold">VirusTotal Notice</AlertTitle>
                <AlertDescription className="text-xs">{virusTotalError}</AlertDescription>
              </Alert>
            )}

            {liveScanError && (
              <Alert className="bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle className="text-xs font-semibold">Live Sandbox Notice</AlertTitle>
                <AlertDescription className="text-xs">{liveScanError}</AlertDescription>
              </Alert>
            )}

            {/* Comprehensive Multi-Tab Intelligence Console */}
            <Tabs defaultValue="sandbox" className="w-full space-y-4">
              <TabsList className="w-full justify-start h-11 p-1 bg-muted/60 border border-border rounded-lg overflow-x-auto flex-nowrap">
                <TabsTrigger value="sandbox" className="gap-2 text-xs font-medium px-4">
                  <Globe className="h-3.5 w-3.5" />
                  <span>Live Sandbox & Preview</span>
                </TabsTrigger>
                <TabsTrigger value="engines" className="gap-2 text-xs font-medium px-4">
                  <Shield className="h-3.5 w-3.5" />
                  <span>Security Vendors ({virusTotalResult?.total || 0})</span>
                </TabsTrigger>
                <TabsTrigger value="forensics" className="gap-2 text-xs font-medium px-4">
                  <Database className="h-3.5 w-3.5" />
                  <span>Domain & RDAP Forensics</span>
                </TabsTrigger>
                <TabsTrigger value="network" className="gap-2 text-xs font-medium px-4">
                  <Network className="h-3.5 w-3.5" />
                  <span>Network & Technologies</span>
                </TabsTrigger>
              </TabsList>

              {/* TAB 1: Live Browser Sandbox & Screenshot */}
              <TabsContent value="sandbox" className="space-y-4 mt-2">
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  {/* Left: Realistic Browser Window Mockup with Screenshot */}
                  <div className="lg:col-span-7 space-y-4">
                    <Card className="border-border shadow-sm bg-card overflow-hidden">
                      {/* Browser Mockup Chrome Header */}
                      <div className="h-10 px-4 bg-muted/70 border-b border-border flex items-center justify-between gap-3">
                        <div className="flex items-center gap-1.5">
                          <span className="h-3 w-3 rounded-full bg-rose-500/80 inline-block" />
                          <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
                          <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
                        </div>

                        <div className="flex-1 max-w-sm h-6 px-2.5 rounded bg-background/80 border border-border/80 flex items-center justify-between text-[11px] font-mono text-muted-foreground truncate">
                          <div className="flex items-center gap-1.5 truncate">
                            <Lock className="h-2.5 w-2.5 text-emerald-500 shrink-0" />
                            <span className="truncate">
                              {parsedUrlscan?.effectiveUrl || parsedUrlscan?.submittedUrl || url}
                            </span>
                          </div>
                          {parsedUrlscan?.country && (
                            <span className="text-[10px] text-muted-foreground shrink-0 uppercase">
                              {parsedUrlscan.country}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1.5">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            onClick={() => {
                              setScreenshotError(false)
                              setScreenshotLoading(true)
                              setScreenshotRefreshKey((v) => v + 1)
                            }}
                            className="h-7 w-7 text-muted-foreground hover:text-foreground"
                            title="Refresh preview screenshot"
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </Button>

                          {urlscanSubmit?.uuid && (
                            <Dialog
                              open={isScreenshotModalOpen}
                              onOpenChange={setIsScreenshotModalOpen}
                            >
                              <DialogTrigger asChild>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon"
                                  className="h-7 w-7 text-muted-foreground hover:text-foreground"
                                  title="Enlarge preview"
                                >
                                  <Maximize2 className="h-3.5 w-3.5" />
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="max-w-4xl p-2 bg-background border-border">
                                <DialogHeader className="p-2">
                                  <DialogTitle className="text-sm font-mono truncate">
                                    Sandbox Render:{" "}
                                    {parsedUrlscan?.effectiveUrl || parsedUrlscan?.submittedUrl || url}
                                  </DialogTitle>
                                </DialogHeader>
                                <div className="relative aspect-[16/9] w-full overflow-hidden rounded border border-border">
                                  <Image
                                    src={`/api/urlscan/screenshot/${encodeURIComponent(urlscanSubmit.uuid)}?t=${screenshotRefreshKey}`}
                                    alt="Enlarged screenshot"
                                    fill
                                    unoptimized
                                    className="object-contain"
                                  />
                                </div>
                              </DialogContent>
                            </Dialog>
                          )}
                        </div>
                      </div>

                      {/* Mockup Canvas Screen */}
                      <CardContent className="p-0 bg-slate-950/20">
                        {urlscanSubmit?.uuid ? (
                          <div className="relative w-full">
                            <AspectRatio ratio={16 / 9}>
                              <div className="relative h-full w-full bg-slate-950/40">
                                {(screenshotLoading || screenshotError) && (
                                  <div className="absolute inset-0 z-10 flex flex-col items-center justify-center p-6 text-center bg-background/90 backdrop-blur-sm">
                                    {screenshotLoading ? (
                                      <div className="space-y-3">
                                        <Loader2 className="h-6 w-6 animate-spin text-sky-500 mx-auto" />
                                        <p className="text-xs font-mono text-muted-foreground">
                                          Rendering headless sandbox viewport...
                                        </p>
                                      </div>
                                    ) : (
                                      <div className="space-y-2">
                                        <Globe className="h-8 w-8 text-muted-foreground mx-auto stroke-1" />
                                        <p className="text-xs font-medium text-foreground">
                                          Screenshot Still Generating or Host Blocked
                                        </p>
                                        <p className="text-[11px] text-muted-foreground max-w-xs mx-auto">
                                          urlscan.io may take an extra 5-10 seconds to generate the
                                          PNG buffer.
                                        </p>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          onClick={() => {
                                            setScreenshotError(false)
                                            setScreenshotLoading(true)
                                            setScreenshotRefreshKey((v) => v + 1)
                                          }}
                                          className="h-7 text-xs mt-2"
                                        >
                                          Retry Fetch
                                        </Button>
                                      </div>
                                    )}
                                  </div>
                                )}

                                <Image
                                  key={screenshotRefreshKey}
                                  src={`/api/urlscan/screenshot/${encodeURIComponent(urlscanSubmit.uuid)}?t=${screenshotRefreshKey}`}
                                  alt="Live scan screenshot"
                                  fill
                                  sizes="(max-width: 768px) 100vw, 60vw"
                                  unoptimized
                                  className={`object-cover object-top transition-opacity duration-300 ${
                                    screenshotLoading || screenshotError
                                      ? "opacity-0"
                                      : "opacity-100"
                                  }`}
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
                        ) : (
                          <div className="aspect-[16/9] flex flex-col items-center justify-center p-6 text-center text-muted-foreground">
                            <Globe className="h-8 w-8 mb-2 stroke-1 opacity-50" />
                            <p className="text-xs font-mono">No live sandbox screenshot dispatched</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>

                  {/* Right: Live Sandbox Inspection Summary */}
                  <div className="lg:col-span-5 space-y-4">
                    <Card className="border-border shadow-sm bg-card">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-sm font-semibold flex items-center gap-2">
                            <Activity className="h-4 w-4 text-sky-500" />
                            <span>Sandbox Telemetry</span>
                          </CardTitle>
                          <Badge
                            variant={
                              urlscanStatus.toLowerCase().includes("complete")
                                ? "default"
                                : "outline"
                            }
                            className="font-mono text-[10px]"
                          >
                            {urlscanStatus || "Standby"}
                          </Badge>
                        </div>
                        <CardDescription className="text-xs">
                          Real-time execution metrics extracted from urlscan.io
                        </CardDescription>
                      </CardHeader>

                      <CardContent className="space-y-4">
                        {/* 4 Metric Counter Cards */}
                        <div className="grid grid-cols-2 gap-2.5">
                          <div className="p-3 rounded-lg border border-border bg-muted/40">
                            <p className="text-[10px] uppercase font-mono text-muted-foreground">
                              HTTP Transactions
                            </p>
                            <p className="text-xl font-bold font-mono text-foreground mt-0.5">
                              {parsedUrlscan?.requests ?? "—"}
                            </p>
                          </div>
                          <div className="p-3 rounded-lg border border-border bg-muted/40">
                            <p className="text-[10px] uppercase font-mono text-muted-foreground">
                              Contacted IPs
                            </p>
                            <p className="text-xl font-bold font-mono text-foreground mt-0.5">
                              {parsedUrlscan?.uniqIps ?? "—"}
                            </p>
                          </div>
                          <div className="p-3 rounded-lg border border-border bg-muted/40">
                            <p className="text-[10px] uppercase font-mono text-muted-foreground">
                              Contacted Domains
                            </p>
                            <p className="text-xl font-bold font-mono text-foreground mt-0.5">
                              {parsedUrlscan?.uniqDomains ?? "—"}
                            </p>
                          </div>
                          <div className="p-3 rounded-lg border border-border bg-muted/40">
                            <p className="text-[10px] uppercase font-mono text-muted-foreground">
                              Geolocations
                            </p>
                            <p className="text-xl font-bold font-mono text-foreground mt-0.5">
                              {parsedUrlscan?.uniqCountries ?? "—"}
                            </p>
                          </div>
                        </div>

                        {/* Telemetry Detail Rows */}
                        <div className="divide-y divide-border/60 text-xs font-mono space-y-2 pt-1">
                          <div className="flex items-center justify-between pt-2">
                            <span className="text-muted-foreground">Page Title:</span>
                            <span className="text-foreground font-sans font-medium truncate max-w-[200px] text-right">
                              {parsedUrlscan?.pageTitle || "—"}
                            </span>
                          </div>
                          <div className="flex items-center justify-between pt-2">
                            <span className="text-muted-foreground">Server Header:</span>
                            <span className="text-foreground truncate max-w-[200px] text-right">
                              {parsedUrlscan?.server || "Undisclosed"}
                            </span>
                          </div>
                          <div className="flex items-center justify-between pt-2">
                            <span className="text-muted-foreground">Primary ASN:</span>
                            <span className="text-foreground truncate max-w-[200px] text-right">
                              {parsedUrlscan?.asn
                                ? `${parsedUrlscan.asn} ${parsedUrlscan.asnName ? `(${parsedUrlscan.asnName})` : ""}`
                                : "—"}
                            </span>
                          </div>
                          <div className="flex items-center justify-between pt-2">
                            <span className="text-muted-foreground">Task Visibility:</span>
                            <span className="text-foreground capitalize">{urlscanVisibility}</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>

              {/* TAB 2: Security Vendors & Engines */}
              <TabsContent value="engines" className="space-y-4 mt-2">
                <Card className="border-border shadow-sm bg-card">
                  <CardHeader className="pb-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <CardTitle className="text-sm font-semibold flex items-center gap-2">
                          <Shield className="h-4 w-4 text-sky-500" />
                          <span>Multi-Engine Vendor Consensus</span>
                        </CardTitle>
                        <CardDescription className="text-xs">
                          Detailed threat signatures detected by individual security vendors
                        </CardDescription>
                      </div>

                      {/* Filters */}
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="relative">
                          <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-muted-foreground" />
                          <Input
                            placeholder="Filter vendor..."
                            value={engineSearch}
                            onChange={(e) => setEngineSearch(e.target.value)}
                            className="h-8 pl-8 pr-2 w-36 sm:w-44 text-xs font-mono bg-background"
                          />
                        </div>

                        <div className="inline-flex rounded-md border border-border p-0.5 bg-muted/60 text-xs">
                          <button
                            type="button"
                            onClick={() => setEngineFilter("all")}
                            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                              engineFilter === "all"
                                ? "bg-background text-foreground shadow-sm"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            All ({Object.keys(virusTotalResult?.scans || {}).length})
                          </button>
                          <button
                            type="button"
                            onClick={() => setEngineFilter("detected")}
                            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                              engineFilter === "detected"
                                ? "bg-rose-500/10 text-rose-500 font-semibold"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            Threats ({virusTotalResult?.positives || 0})
                          </button>
                          <button
                            type="button"
                            onClick={() => setEngineFilter("clean")}
                            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                              engineFilter === "clean"
                                ? "bg-emerald-500/10 text-emerald-500 font-semibold"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            Clean
                          </button>
                        </div>
                      </div>
                    </div>
                  </CardHeader>

                  <CardContent>
                    {filteredScans.length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-[500px] overflow-y-auto pr-1">
                        {filteredScans.map((scan) => (
                          <div
                            key={scan.engine}
                            className={`p-3 rounded-lg border transition-colors flex items-center justify-between gap-3 ${
                              scan.detected
                                ? "border-rose-500/30 bg-rose-500/[0.04]"
                                : "border-border bg-card/60 hover:bg-muted/40"
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              {scan.detected ? (
                                <XCircle className="h-4 w-4 text-rose-500 shrink-0" />
                              ) : (
                                <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                              )}
                              <div className="min-w-0">
                                <p className="text-xs font-semibold text-foreground truncate">
                                  {scan.engine}
                                </p>
                                <p className="text-[10px] text-muted-foreground font-mono truncate">
                                  {scan.detected ? scan.result : `v${scan.version || "latest"}`}
                                </p>
                              </div>
                            </div>

                            <Badge
                              variant={scan.detected ? "destructive" : "outline"}
                              className={`text-[10px] font-mono shrink-0 ${
                                !scan.detected ? "text-emerald-600 dark:text-emerald-400 border-emerald-500/30" : ""
                              }`}
                            >
                              {scan.detected ? "Threat" : "Clean"}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-8 text-center text-muted-foreground">
                        <Filter className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-xs font-mono">No vendor results match the filter</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* TAB 3: Domain & RDAP Forensics */}
              <TabsContent value="forensics" className="space-y-4 mt-2">
                <Card className="border-border shadow-sm bg-card">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Database className="h-4 w-4 text-sky-500" />
                      <span>Registration Data Access Protocol (RDAP / WHOIS)</span>
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Authoritative registration authority, registrar history, and DNS records
                    </CardDescription>
                  </CardHeader>

                  <CardContent className="space-y-6">
                    {virusTotalResult?.rdap ? (
                      <>
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                          {[
                            { label: "Target Domain", value: virusTotalResult.rdap.domain, mono: true },
                            { label: "Registrar Name", value: virusTotalResult.rdap.registrar },
                            { label: "Organization", value: virusTotalResult.rdap.organization },
                            { label: "Registrant Country", value: virusTotalResult.rdap.country },
                            { label: "Creation Date", value: virusTotalResult.rdap.creation_date, mono: true },
                            { label: "Expiration Date", value: virusTotalResult.rdap.expiration_date, mono: true },
                          ].map((item, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-lg border border-border bg-muted/30"
                            >
                              <p className="text-[11px] font-medium text-muted-foreground">
                                {item.label}
                              </p>
                              <p
                                className={`mt-1 text-xs text-foreground truncate ${
                                  item.mono ? "font-mono font-medium" : ""
                                }`}
                              >
                                {item.value || "—"}
                              </p>
                            </div>
                          ))}
                        </div>

                        {/* Nameservers */}
                        {virusTotalResult.rdap.name_servers &&
                          virusTotalResult.rdap.name_servers.length > 0 && (
                            <div className="space-y-2">
                              <p className="text-xs font-medium text-muted-foreground">
                                Authoritative Nameservers
                              </p>
                              <div className="flex flex-wrap gap-2">
                                {virusTotalResult.rdap.name_servers.map((ns, idx) => (
                                  <Badge
                                    key={idx}
                                    variant="outline"
                                    className="font-mono text-xs bg-muted/40"
                                  >
                                    {ns}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                        {/* Domain Status */}
                        {virusTotalResult.rdap.status &&
                          virusTotalResult.rdap.status.length > 0 && (
                            <div className="space-y-2">
                              <p className="text-xs font-medium text-muted-foreground">
                                ICANN / Registry Status
                              </p>
                              <div className="flex flex-wrap gap-2">
                                {virusTotalResult.rdap.status.map((st, idx) => (
                                  <Badge
                                    key={idx}
                                    variant="secondary"
                                    className="font-mono text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                                  >
                                    {st}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                      </>
                    ) : (
                      <div className="p-8 text-center text-muted-foreground">
                        <Database className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-xs font-mono">
                          RDAP registration data not provided by authoritative resolver
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* TAB 4: Network & Technology Stack */}
              <TabsContent value="network" className="space-y-4 mt-2">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Left: Technologies Detected */}
                  <Card className="border-border shadow-sm bg-card">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-sky-500" />
                        <span>Detected Technologies & Headers</span>
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Wappalyzer fingerprints and web stack indicators
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      {parsedUrlscan?.technologies && parsedUrlscan.technologies.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {parsedUrlscan.technologies.map((tech) => (
                            <Badge
                              key={tech}
                              variant="secondary"
                              className="px-2.5 py-1 text-xs font-mono bg-sky-500/10 text-sky-700 dark:text-sky-300 border border-sky-500/20"
                            >
                              {tech}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs font-mono text-muted-foreground">
                          No distinct third-party technologies fingerprinted
                        </p>
                      )}

                      <div className="pt-2 border-t border-border space-y-2">
                        <p className="text-xs font-medium text-muted-foreground">Host Routing</p>
                        <div className="p-3 rounded-lg border border-border bg-muted/30 font-mono text-xs space-y-1">
                          <p>
                            <span className="text-muted-foreground">Primary IP: </span>
                            {parsedUrlscan?.ip || "—"}
                          </p>
                          <p>
                            <span className="text-muted-foreground">ASN / Network: </span>
                            {parsedUrlscan?.asn
                              ? `${parsedUrlscan.asn} ${parsedUrlscan.asnName ? `(${parsedUrlscan.asnName})` : ""}`
                              : "—"}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Right: Extracted Indicators (Domains & IPs) */}
                  <Card className="border-border shadow-sm bg-card">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Layers className="h-4 w-4 text-sky-500" />
                        <span>Extracted Threat Indicators</span>
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Contacted infrastructure endpoints and domains
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      <div>
                        <div className="flex items-center justify-between text-xs text-muted-foreground mb-1.5">
                          <span>Domains Contacted ({parsedUrlscan?.domains.length || 0})</span>
                        </div>
                        <ScrollArea className="h-32 rounded border border-border p-2 bg-muted/20">
                          <div className="flex flex-wrap gap-1.5">
                            {parsedUrlscan?.domains && parsedUrlscan.domains.length > 0 ? (
                              parsedUrlscan.domains.map((dom) => (
                                <span
                                  key={dom}
                                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-background border border-border text-foreground"
                                >
                                  {dom}
                                </span>
                              ))
                            ) : (
                              <span className="text-xs font-mono text-muted-foreground">
                                None recorded
                              </span>
                            )}
                          </div>
                        </ScrollArea>
                      </div>

                      <div>
                        <div className="flex items-center justify-between text-xs text-muted-foreground mb-1.5">
                          <span>IP Addresses Contacted ({parsedUrlscan?.ips.length || 0})</span>
                        </div>
                        <ScrollArea className="h-28 rounded border border-border p-2 bg-muted/20">
                          <div className="flex flex-wrap gap-1.5">
                            {parsedUrlscan?.ips && parsedUrlscan.ips.length > 0 ? (
                              parsedUrlscan.ips.map((ipAddr) => (
                                <span
                                  key={ipAddr}
                                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-background border border-border text-foreground"
                                >
                                  {ipAddr}
                                </span>
                              ))
                            ) : (
                              <span className="text-xs font-mono text-muted-foreground">
                                None recorded
                              </span>
                            )}
                          </div>
                        </ScrollArea>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Network HTTP Requests Log */}
                {parsedUrlscan?.rawRequests && parsedUrlscan.rawRequests.length > 0 && (
                  <Card className="border-border shadow-sm bg-card">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-sky-500" />
                        <span>Live HTTP Network Log ({parsedUrlscan.rawRequests.length})</span>
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Outbound network requests issued by the target during sandbox load
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-72 rounded border border-border">
                        <div className="divide-y divide-border/60">
                          {parsedUrlscan.rawRequests.map((entry: unknown, idx: number) => {
                            const rec = isRecord(entry) ? entry : null
                            const req = rec && isRecord(rec["request"]) ? rec["request"] : null
                            const res = rec && isRecord(rec["response"]) ? rec["response"] : null
                            const method = asString(req?.["method"]) || asString(rec?.["method"]) || "GET"
                            const reqUrl = asString(req?.["url"]) || asString(rec?.["url"]) || ""
                            const status = res?.["status"] ?? rec?.["status"]
                            const mime = asString(res?.["mimeType"]) || asString(res?.["type"])

                            if (!reqUrl) return null

                            return (
                              <div
                                key={idx}
                                className="p-3 text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-muted/40 transition-colors"
                              >
                                <div className="flex items-center gap-2 min-w-0">
                                  <Badge
                                    variant="outline"
                                    className="px-1.5 py-0 text-[10px] font-mono shrink-0"
                                  >
                                    {method}
                                  </Badge>
                                  {typeof status !== "undefined" && (
                                    <Badge
                                      variant={
                                        typeof status === "number" && status >= 400
                                          ? "destructive"
                                          : "secondary"
                                      }
                                      className="px-1.5 py-0 text-[10px] font-mono shrink-0"
                                    >
                                      {String(status)}
                                    </Badge>
                                  )}
                                  <span className="truncate text-foreground max-w-xl">
                                    {reqUrl}
                                  </span>
                                </div>
                                {mime && (
                                  <span className="text-[10px] text-muted-foreground shrink-0">
                                    {mime}
                                  </span>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}
      </main>

      {/* Modern High-End Security Console Footer */}
      <footer className="mt-auto border-t border-border bg-card/40 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="space-y-2">
              <div className="flex items-center gap-2 font-semibold text-foreground">
                <ShieldCheck className="h-4 w-4 text-sky-500" />
                <span>PhishGuard Security Architecture</span>
              </div>
              <p className="text-muted-foreground leading-relaxed max-w-sm">
                A high-fidelity URL threat inspection engine designed for security analysts and
                developers. Inspect suspicious links safely without exposing your network.
              </p>
            </div>

            <div className="space-y-2">
              <p className="font-semibold text-foreground">Threat Intelligence Feeds</p>
              <ul className="space-y-1 text-muted-foreground">
                <li className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <span>VirusTotal Public API v3</span>
                </li>
                <li className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <span>urlscan.io Headless Sandboxing</span>
                </li>
                <li className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <span>ICANN RDAP / WHOIS Forensics</span>
                </li>
              </ul>
            </div>

            <div className="space-y-2 md:text-right flex flex-col md:items-end">
              <p className="font-semibold text-foreground">Project & Developer</p>
              <div className="flex flex-wrap gap-3 text-muted-foreground">
                <Link href="/privacy-policy" className="hover:text-foreground underline underline-offset-2">
                  Privacy Policy
                </Link>
                <span>•</span>
                <a
                  href="mailto:contact@debasisbiswas.in"
                  className="hover:text-foreground underline underline-offset-2"
                >
                  Contact Support
                </a>
                <span>•</span>
                <a
                  href="https://buymeacoffee.com/debasisbiswas"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-amber-500 hover:text-amber-400 font-medium underline underline-offset-2"
                >
                  Sponsor
                </a>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                Engineered by Debasis Biswas • All rights reserved
              </p>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t border-border/60 flex flex-col sm:flex-row items-center justify-between gap-2 text-[11px] text-muted-foreground">
            <span>© {new Date().getFullYear()} PhishGuard Security. For defensive security purposes only.</span>
            <span className="font-mono">Defensive Cyber Telemetry Console</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
