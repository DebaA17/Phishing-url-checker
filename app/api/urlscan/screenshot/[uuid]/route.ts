import { NextResponse } from "next/server"

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 20000) {
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

export async function GET(_request: Request, context: { params: Promise<{ uuid: string }> }) {
  try {
    const { uuid } = await context.params

    if (!uuid) {
      return NextResponse.json({ error: "uuid is required" }, { status: 400 })
    }

    const apiKey = process.env.URLSCAN_API_KEY
    const upstreamUrl = `https://urlscan.io/screenshots/${encodeURIComponent(uuid)}.png`

    const upstream = await fetchWithTimeout(
      upstreamUrl,
      {
        headers: {
          Accept: "image/png,image/*;q=0.8,*/*;q=0.5",
          ...(apiKey ? { "API-Key": apiKey } : {}),
        },
        cache: "no-store",
      },
      20000,
    )

    const bytes = await upstream.arrayBuffer()

    return new NextResponse(bytes, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("content-type") || "image/png",
        "Cache-Control": "no-store",
      },
    })
  } catch (error) {
    console.error("screenshot proxy error:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Internal server error" },
      { status: 500 },
    )
  }
}
