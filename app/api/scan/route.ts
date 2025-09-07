import { type NextRequest, NextResponse } from "next/server"

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

// Add timeout wrapper for fetch requests
async function fetchWithTimeout(url: string, options: any = {}, timeout = 10000) {
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

async function getRDAPInfo(domain: string): Promise<RDAPResponse | null> {
  try {
    // Extract domain from URL
    const urlObj = new URL(domain.startsWith("http") ? domain : `https://${domain}`)
    const hostname = urlObj.hostname

    console.log(`Getting RDAP info for domain: ${hostname}`)

    // Use RDAP.ORG client API
    const rdapUrl = `https://client.rdap.org/?type=domain&object=${encodeURIComponent(hostname)}`

    console.log(`RDAP URL: ${rdapUrl}`)

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
      console.warn(`RDAP API returned status: ${response.status}`)

      // Try alternative RDAP approach - direct API call
      const directRdapUrl = `https://rdap.verisign.com/com/v1/domain/${hostname}`

      try {
        const directResponse = await fetchWithTimeout(
          directRdapUrl,
          {
            headers: {
              Accept: "application/rdap+json",
              "User-Agent": "PhishingURLScanner/1.0",
            },
          },
          10000,
        )

        if (directResponse.ok) {
          const directData = await directResponse.json()
          return parseRDAPData(directData, hostname)
        }
      } catch (directError) {
        console.warn("Direct RDAP API also failed:", directError.message)
      }

      // If both fail, return basic info
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

    const contentType = response.headers.get("content-type")
    console.log(`RDAP response content-type: ${contentType}`)

    const text = await response.text()
    console.log(`RDAP response preview: ${text.substring(0, 200)}...`)

    if (!text || text.trim().length === 0) {
      console.warn("RDAP returned empty response")
      return null
    }

    let data
    try {
      data = JSON.parse(text)
    } catch (parseError) {
      console.warn("RDAP returned invalid JSON:", text.substring(0, 100))
      return null
    }

    return parseRDAPData(data, hostname)
  } catch (error) {
    console.error("RDAP lookup failed:", error)
    return null
  }
}

function parseRDAPData(data: any, hostname: string): RDAPResponse {
  console.log("Parsing RDAP data:", JSON.stringify(data, null, 2).substring(0, 500))

  // Handle different RDAP response formats
  const domain = data.ldhName || data.unicodeName || hostname

  // Extract registrar information
  let registrar = "Unknown"
  if (data.entities) {
    const registrarEntity = data.entities.find((entity: any) => entity.roles && entity.roles.includes("registrar"))
    if (registrarEntity && registrarEntity.vcardArray) {
      const vcard = registrarEntity.vcardArray[1]
      const orgField = vcard.find((field: any) => field[0] === "org")
      if (orgField) {
        registrar = orgField[3]
      }
    }
  }

  // Extract dates
  let creationDate = "Unknown"
  let expirationDate = "Unknown"

  if (data.events) {
    const registrationEvent = data.events.find((event: any) => event.eventAction === "registration")
    const expirationEvent = data.events.find((event: any) => event.eventAction === "expiration")

    if (registrationEvent) {
      creationDate = new Date(registrationEvent.eventDate).toLocaleDateString()
    }
    if (expirationEvent) {
      expirationDate = new Date(expirationEvent.eventDate).toLocaleDateString()
    }
  }

  // Extract name servers
  const nameServers = data.nameservers ? data.nameservers.map((ns: any) => ns.ldhName || ns.unicodeName) : []

  // Extract status
  const status = data.status || []

  // Extract organization and country
  let organization = "Unknown"
  let country = "Unknown"

  if (data.entities) {
    const registrantEntity = data.entities.find((entity: any) => entity.roles && entity.roles.includes("registrant"))
    if (registrantEntity && registrantEntity.vcardArray) {
      const vcard = registrantEntity.vcardArray[1]
      const orgField = vcard.find((field: any) => field[0] === "org")
      const countryField = vcard.find((field: any) => field[0] === "adr")

      if (orgField) {
        organization = orgField[3]
      }
      if (countryField && countryField[3] && countryField[3][6]) {
        country = countryField[3][6]
      }
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

async function logToTelegram(url: string, ip: string, userAgent: string, result: any) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN
  const userId = process.env.TELEGRAM_USER_ID

  if (!botToken || !userId) {
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

  const message = `🔍 URL Scan Alert
  
📅 Time: ${timestamp} UTC
🌐 URL: ${url}
🔗 IP: ${ip}
🖥️ User Agent: ${userAgent.substring(0, 100)}${userAgent.length > 100 ? "..." : ""}
⚠️ Threat Level: ${result.threatLevel}
🛡️ Detection: ${result.positives}/${result.total}
🏢 Organization: ${result.rdap?.organization || "Unknown"}
🌍 Country: ${result.rdap?.country || "Unknown"}
📋 Registrar: ${result.rdap?.registrar || "Unknown"}
  
#URLScan #Security`

  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        chat_id: userId,
        text: message,
        parse_mode: "HTML",
      }),
    })
    console.log("Telegram notification sent successfully")
  } catch (error) {
    console.error("Failed to send Telegram notification:", error)
  }
}

function getClientIP(request: NextRequest): string {
  // Try multiple headers in order of preference
  const headers = [
    "cf-connecting-ip", // Cloudflare
    "x-real-ip", // Nginx
    "x-forwarded-for", // Standard proxy header
    "x-client-ip", // Apache
    "x-cluster-client-ip", // Cluster
    "x-forwarded", // Proxy
    "forwarded-for", // Proxy
    "forwarded", // RFC 7239
  ]

  for (const header of headers) {
    const value = request.headers.get(header)
    if (value) {
      // Handle comma-separated IPs (take the first one)
      const ip = value.split(",")[0].trim()
      if (ip && ip !== "unknown") {
        console.log(`IP found in header ${header}: ${ip}`)
        return ip
      }
    }
  }

  // Try to get IP from request object
  const requestIP = (request as any).ip
  if (requestIP) {
    console.log(`IP found in request.ip: ${requestIP}`)
    return requestIP
  }

  console.log("No IP found in any header, using unknown")
  return "unknown"
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

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY

    if (!apiKey) {
      return NextResponse.json({ error: "VirusTotal API key not configured" }, { status: 500 })
    }

    // Get client information for logging
    const clientIP = getClientIP(request)
    const userAgent = request.headers.get("user-agent") || "unknown"

    console.log(`Scan request from IP: ${clientIP}, User-Agent: ${userAgent}`)

    // Get RDAP information in parallel
    const rdapPromise = getRDAPInfo(url)

    // Submit URL for scanning
    const submitResponse = await fetchWithTimeout(
      "https://www.virustotal.com/vtapi/v2/url/scan",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          apikey: apiKey,
          url: url,
        }),
      },
      10000,
    )

    if (!submitResponse.ok) {
      throw new Error("Failed to submit URL to VirusTotal")
    }

    // Wait a moment then get the report
    await new Promise((resolve) => setTimeout(resolve, 3000))

    const reportResponse = await fetchWithTimeout(
      `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${encodeURIComponent(url)}&allinfo=1`,
      {},
      10000,
    )

    if (!reportResponse.ok) {
      throw new Error("Failed to get VirusTotal report")
    }

    const reportData: VirusTotalResponse = await reportResponse.json()
    const rdapData = await rdapPromise

    let result
    if (reportData.response_code === 1) {
      // Report available
      const threatLevel = determineThreatLevel(reportData.positives || 0, reportData.total || 0)

      result = {
        url,
        threatLevel,
        positives: reportData.positives || 0,
        total: reportData.total || 0,
        scanDate: formatScanDate(reportData.scan_date || new Date().toISOString()),
        permalink: reportData.permalink,
        details: reportData.verbose_msg,
        scans: reportData.scans || {},
        rdap: rdapData,
      }
    } else if (reportData.response_code === 0) {
      // URL not in database, but scan was queued
      result = {
        url,
        threatLevel: "unknown" as const,
        positives: 0,
        total: 0,
        scanDate: formatScanDate(new Date().toISOString()),
        details: "URL queued for scanning. Please try again in a few minutes.",
        scans: {},
        rdap: rdapData,
      }
    } else {
      throw new Error(reportData.verbose_msg || "Unknown error from VirusTotal")
    }

    // Log to Telegram
    await logToTelegram(url, clientIP, userAgent, result)

    return NextResponse.json(result)
  } catch (error) {
    console.error("Scan error:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Internal server error" },
      { status: 500 },
    )
  }
}
