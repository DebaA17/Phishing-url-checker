import { type NextRequest, NextResponse } from "next/server"

interface TurnstileVerificationResponse {
  success: boolean
  "error-codes"?: string[]
}

type UrlscanVisibility = "public" | "private" | "unlisted"

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

function isHttpUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl)
    return parsed.protocol === "http:" || parsed.protocol === "https:"
  } catch {
    return false
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
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    },
    10000,
  )

  if (!response.ok) {
    throw new Error("Turnstile verification request failed")
  }

  const data: TurnstileVerificationResponse = await response.json()
  if (!data.success) {
    console.warn("Turnstile verification failed:", data["error-codes"] || [])
  }

  return data.success
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

export async function POST(request: NextRequest) {
  try {
    const { url, visibility, turnstileToken } = await request.json()

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    if (!isHttpUrl(url)) {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    const scanVisibility: UrlscanVisibility =
      visibility === "private" || visibility === "unlisted" ? visibility : "public"

    if (!turnstileToken || typeof turnstileToken !== "string") {
      return NextResponse.json({ error: "Turnstile token is required" }, { status: 400 })
    }

    const urlscanApiKey = process.env.URLSCAN_API_KEY
    const turnstileSecret = process.env.TURNSTILE_SECRET_KEY

    if (!urlscanApiKey) {
      return NextResponse.json({ error: "Live scan API key not configured" }, { status: 500 })
    }

    if (!turnstileSecret) {
      return NextResponse.json({ error: "Turnstile secret key not configured" }, { status: 500 })
    }

    const clientIP = getClientIP(request)
    const isTurnstileValid = await verifyTurnstileToken(
      turnstileSecret,
      turnstileToken,
      clientIP !== "unknown" ? clientIP : undefined,
    )

    if (!isTurnstileValid) {
      return NextResponse.json({ error: "Turnstile verification failed. Please try again." }, { status: 403 })
    }

    const submitResponse = await fetchWithTimeout(
      "https://urlscan.io/api/v1/scan/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": urlscanApiKey,
        },
        body: JSON.stringify({
          url,
          visibility: scanVisibility,
        }),
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
      return NextResponse.json({ error: message }, { status: submitResponse.status })
    }

    return NextResponse.json(payload)
  } catch (error) {
    console.error("urlscan submit error:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Internal server error" },
      { status: 500 },
    )
  }
}
