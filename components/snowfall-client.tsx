"use client"
import React from "react"
import Snowfall from "react-snowfall"

function isSnowfallSeason() {
  const now = new Date()
  const month = now.getMonth() // 0-indexed: 10 = November, 0 = January
  const date = now.getDate()
  // Nov 1 to Dec 31
  if (month === 10 && date >= 1) return true
  if (month === 11) return true
  // Jan 1 to Jan 28
  if (month === 0 && date <= 28) return true
  return false
}

export default function SnowfallClient() {
  if (!isSnowfallSeason()) return null
  return (
    <div style={{ pointerEvents: 'none', position: 'fixed', inset: 0, zIndex: 9999 }}>
      <Snowfall color="#fff" snowflakeCount={120} style={{ width: '100vw', height: '100vh' }} />
    </div>
  )
}