import { type NextRequest, NextResponse } from "next/server"

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

export async function GET(_request: NextRequest, context: { params: Promise<{ uuid: string }> }) {
  try {
    const { uuid } = await context.params

    if (!uuid) {
      return NextResponse.json({ error: "uuid is required" }, { status: 400 })
    }

    const urlscanApiKey = process.env.URLSCAN_API_KEY

    const response = await fetchWithTimeout(
      `https://urlscan.io/api/v1/result/${encodeURIComponent(uuid)}/`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          ...(urlscanApiKey ? { "API-Key": urlscanApiKey } : {}),
        },
      },
      20000,
    )

    const text = await response.text()
    let payload: any = null
    try {
      payload = text ? JSON.parse(text) : null
    } catch {
      payload = null
    }

    if (!response.ok) {
      // urlscan often returns 404 while scan is still processing
      const message = payload?.message || payload?.description || (response.status === 404 ? "Result not ready" : "Failed to fetch live scan result")
      return NextResponse.json({ error: message }, { status: response.status })
    }

    return NextResponse.json(payload)
  } catch (error) {
    console.error("urlscan result error:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Internal server error" },
      { status: 500 },
    )
  }
}
