import { type NextRequest, NextResponse } from "next/server"


type UrlscanVisibility = "public" | "private" | "unlisted"

interface TurnstileVerificationResponse {
  success: boolean
  "error-codes"?: string[]
}

interface VirusTotalResponse {
  response_code: number
  verbose_msg: string
  resource: string
  scan_id?: string
  scan_date?: string
  permalink?: string
  positives?: number
  total?: number
  scans?: Record<string, { detected: boolean; version: string; result: string; update: string }>
}

interface RDAPResponse {
  domain: string
  registrar: string
  creation_date: string
  expiration_date: string
  name_servers: string[]
  status: string[]
  country: string
  organization: string
}

// SSRF protection helper
function isSafePublicDomain(hostname: string): boolean {
  const forbidden = ["localhost", "127.0.0.1", "::1"]
  if (forbidden.includes(hostname)) return false

  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  if (ipv4.test(hostname)) {
    const parts = hostname.split(".").map(Number)
    if (
      parts[0] === 10 ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    ) {
      return false
    }
    if (parts[0] === 127) return false
  }

  if (/^[a-fA-F0-9:]+$/.test(hostname) && hostname.includes(":")) return false

  if (!/^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$/.test(hostname)) {
    return false
  }

  return true
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 15000) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeout)

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    })
    clearTimeout(timeoutId)
    return response
  } catch (error) {
    clearTimeout(timeoutId)
    throw error
  }
}

function getClientIP(request: NextRequest): string {
  const headers = [
    "cf-connecting-ip",
    "x-real-ip",
    "x-forwarded-for",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-forwarded",
    "forwarded-for",
    "forwarded",
  ]

  for (const header of headers) {
    const value = request.headers.get(header)
    if (value) {
      const ip = value.split(",")[0].trim()
      if (ip && ip !== "unknown") return ip
    }
  }

  const requestIP = (request as any).ip
  return requestIP || "unknown"
}

async function logToTelegram(url: string, ip: string, userAgent: string, result: any) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN
  const chatId = process.env.TELEGRAM_CHAT_ID || process.env.TELEGRAM_USER_ID

  if (!botToken || !chatId) {
    console.warn("Telegram credentials not configured")
    return
  }

  const timestamp = new Date().toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })

  const safeUrl = typeof url === "string" ? url : "unknown"
  const threatLevel = result?.threatLevel || "unknown"
  const positives = typeof result?.positives === "number" ? result.positives : 0
  const total = typeof result?.total === "number" ? result.total : 0

  const message = `URL Scan Alert\n\nTime: ${timestamp} UTC\nURL: ${safeUrl}\nIP: ${ip}\nUser Agent: ${userAgent.substring(0, 100)}${userAgent.length > 100 ? "..." : ""}\nThreat Level: ${threatLevel}\nDetection: ${positives}/${total}\nOrganization: ${result?.rdap?.organization || "Unknown"}\nCountry: ${result?.rdap?.country || "Unknown"}\nRegistrar: ${result?.rdap?.registrar || "Unknown"}`

  try {
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
      }),
    })
    if (!resp.ok) {
      const text = await resp.text().catch(() => "")
      console.warn("Telegram notification failed:", resp.status, text)
    }
  } catch (error) {
    console.error("Failed to send Telegram notification:", error)
  }
}

async function verifyTurnstileToken(secret: string, token: string, remoteip?: string): Promise<boolean> {
  const body = new URLSearchParams({
    secret,
    response: token,
  })

  if (remoteip) {
    body.append("remoteip", remoteip)
  }

  const response = await fetchWithTimeout(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    },
    10000,
  )

  if (!response.ok) throw new Error("Turnstile verification request failed")

  const data: TurnstileVerificationResponse = await response.json()
  if (!data.success) {
    console.warn("Turnstile verification failed:", data["error-codes"] || [])
  }

  return data.success
}

function determineThreatLevel(positives: number, total: number): "safe" | "suspicious" | "malicious" | "unknown" {
  if (total === 0) return "unknown"
  const ratio = positives / total
  if (ratio === 0) return "safe"
  if (ratio < 0.1) return "suspicious"
  return "malicious"
}

function formatScanDate(dateString: string): string {
  try {
    const date = new Date(dateString)
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    })
  } catch {
    return new Date().toLocaleString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    })
  }
}

function parseRDAPData(data: any, hostname: string): RDAPResponse {
  const domain = data.ldhName || data.unicodeName || hostname

  let registrar = "Unknown"
  if (data.entities) {
    const registrarEntity = data.entities.find((entity: any) => entity.roles && entity.roles.includes("registrar"))
    if (registrarEntity && registrarEntity.vcardArray) {
      const vcard = registrarEntity.vcardArray[1]
      const orgField = vcard.find((field: any) => field[0] === "org")
      if (orgField) registrar = orgField[3]
    }
  }

  let creationDate = "Unknown"
  let expirationDate = "Unknown"

  if (data.events) {
    const registrationEvent = data.events.find((event: any) => event.eventAction === "registration")
    const expirationEvent = data.events.find((event: any) => event.eventAction === "expiration")

    if (registrationEvent) creationDate = new Date(registrationEvent.eventDate).toLocaleDateString()
    if (expirationEvent) expirationDate = new Date(expirationEvent.eventDate).toLocaleDateString()
  }

  const nameServers = data.nameservers ? data.nameservers.map((ns: any) => ns.ldhName || ns.unicodeName) : []
  const status = data.status || []

  let organization = "Unknown"
  let country = "Unknown"

  if (data.entities) {
    const registrantEntity = data.entities.find((entity: any) => entity.roles && entity.roles.includes("registrant"))
    if (registrantEntity && registrantEntity.vcardArray) {
      const vcard = registrantEntity.vcardArray[1]
      const orgField = vcard.find((field: any) => field[0] === "org")
      const countryField = vcard.find((field: any) => field[0] === "adr")

      if (orgField) organization = orgField[3]
      if (countryField && countryField[3] && countryField[3][6]) country = countryField[3][6]
    }
  }

  return {
    domain,
    registrar,
    creation_date: creationDate,
    expiration_date: expirationDate,
    name_servers: nameServers,
    status,
    country,
    organization,
  }
}

async function getRDAPInfo(domain: string): Promise<RDAPResponse | null> {
  try {
    const urlObj = new URL(domain.startsWith("http") ? domain : `https://${domain}`)
    const hostname = urlObj.hostname

    if (!isSafePublicDomain(hostname)) {
      console.warn(`Blocked potential SSRF: unsafe domain ${hostname}`)
      return null
    }

    const rdapUrl = `https://client.rdap.org/?type=domain&object=${encodeURIComponent(hostname)}`

    const response = await fetchWithTimeout(
      rdapUrl,
      {
        headers: {
          Accept: "application/json",
          "User-Agent": "PhishingURLScanner/1.0",
        },
      },
      15000,
    )

    if (!response.ok) {
      return {
        domain: hostname,
        registrar: "Unknown",
        creation_date: "Unknown",
        expiration_date: "Unknown",
        name_servers: [],
        status: [],
        country: "Unknown",
        organization: "Unknown",
      }
    }

    const text = await response.text()
    if (!text || text.trim().length === 0) return null

    let data: any
    try {
      data = JSON.parse(text)
    } catch {
      return null
    }

    return parseRDAPData(data, hostname)
  } catch (error) {
    console.error("RDAP lookup failed:", error)
    return null
  }
}

function isHttpUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl)
    return parsed.protocol === "http:" || parsed.protocol === "https:"
  } catch {
    return false
  }
}

export async function POST(request: NextRequest) {
  try {
    const { url, visibility, turnstileToken } = await request.json()

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    if (!isHttpUrl(url)) {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    if (!turnstileToken || typeof turnstileToken !== "string") {
      return NextResponse.json({ error: "Turnstile token is required" }, { status: 400 })
    }

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY
    const turnstileSecret = process.env.TURNSTILE_SECRET_KEY

    if (!vtApiKey) {
      return NextResponse.json({ error: "VirusTotal API key not configured" }, { status: 500 })
    }

    if (!turnstileSecret) {
      return NextResponse.json({ error: "Turnstile secret key not configured" }, { status: 500 })
    }

    const clientIP = getClientIP(request)
    const userAgent = request.headers.get("user-agent") || "unknown"
    const isTurnstileValid = await verifyTurnstileToken(
      turnstileSecret,
      turnstileToken,
      clientIP !== "unknown" ? clientIP : undefined,
    )

    if (!isTurnstileValid) {
      return NextResponse.json({ error: "Turnstile verification failed. Please try again." }, { status: 403 })
    }

    // RDAP in parallel
    const rdapPromise = getRDAPInfo(url)

    // VirusTotal flow
    const vtTask = (async () => {
      const submitResponse = await fetchWithTimeout(
        "https://www.virustotal.com/vtapi/v2/url/scan",
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ apikey: vtApiKey, url }),
        },
        10000,
      )

      if (!submitResponse.ok) throw new Error("Failed to submit URL to VirusTotal")

      await new Promise((resolve) => setTimeout(resolve, 3000))

      const reportResponse = await fetchWithTimeout(
        `https://www.virustotal.com/vtapi/v2/url/report?apikey=${vtApiKey}&resource=${encodeURIComponent(url)}&allinfo=1`,
        {},
        10000,
      )

      if (!reportResponse.ok) throw new Error("Failed to get VirusTotal report")

      const reportData: VirusTotalResponse = await reportResponse.json()
      const rdap = await rdapPromise

      if (reportData.response_code === 1) {
        const threatLevel = determineThreatLevel(reportData.positives || 0, reportData.total || 0)
        return {
          url,
          threatLevel,
          positives: reportData.positives || 0,
          total: reportData.total || 0,
          scanDate: formatScanDate(reportData.scan_date || new Date().toISOString()),
          permalink: reportData.permalink,
          details: reportData.verbose_msg,
          scans: reportData.scans || {},
          rdap,
        }
      }

      if (reportData.response_code === 0) {
        return {
          url,
          threatLevel: "unknown" as const,
          positives: 0,
          total: 0,
          scanDate: formatScanDate(new Date().toISOString()),
          details: "URL queued for scanning. Please try again in a few minutes.",
          scans: {},
          rdap,
        }
      }

      throw new Error(reportData.verbose_msg || "Unknown error from VirusTotal")
    })()

    // Live scan submit (optional)
    const liveTask = (async () => {
      const liveApiKey = process.env.URLSCAN_API_KEY
      if (!liveApiKey) {
        return { submit: null, error: "Live scan API key not configured" }
      }

      const scanVisibility: UrlscanVisibility =
        visibility === "private" || visibility === "unlisted" ? visibility : "public"

      const submitResponse = await fetchWithTimeout(
        "https://urlscan.io/api/v1/scan/",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "API-Key": liveApiKey,
          },
          body: JSON.stringify({ url, visibility: scanVisibility }),
        },
        20000,
      )

      const payloadText = await submitResponse.text()
      let payload: any = null
      try {
        payload = payloadText ? JSON.parse(payloadText) : null
      } catch {
        payload = null
      }

      if (!submitResponse.ok) {
        const message = payload?.message || payload?.description || "Failed to submit live scan"
        return { submit: null, error: message }
      }

      return { submit: payload, error: null }
    })()

    const [vtOutcome, liveOutcome] = await Promise.allSettled([vtTask, liveTask])

    const virusTotal = vtOutcome.status === "fulfilled" ? vtOutcome.value : null
    const virusTotalError =
      vtOutcome.status === "rejected" ? (vtOutcome.reason instanceof Error ? vtOutcome.reason.message : "Primary scan failed") : null

    const live =
      liveOutcome.status === "fulfilled"
        ? liveOutcome.value
        : { submit: null, error: liveOutcome.reason instanceof Error ? liveOutcome.reason.message : "Live scan failed" }

    if (virusTotal) {
      // Fire and forget; do not block response.
      logToTelegram(url, clientIP, userAgent, virusTotal).catch(() => {})
    }

    return NextResponse.json({
      virusTotal,
      virusTotalError,
      liveSubmit: live.submit,
      liveError: live.error,
    })
  } catch (error) {
    console.error("combined scan error:", error)
    return NextResponse.json({ error: error instanceof Error ? error.message : "Internal server error" }, { status: 500 })
  }
}
