"use client"

import { useEffect } from "react"
import { AlertTriangle, Home, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export default function NotFound() {
  useEffect(() => {
    // Redirect to debasisbiswas.me after 5 seconds
    const timer = setTimeout(() => {
      window.location.href = "https://debasisbiswas.me"
    }, 5000)

    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-orange-100 flex items-center justify-center p-4">
      <Card className="max-w-md w-full text-center">
        <CardHeader>
          <div className="flex justify-center mb-4">
            <div className="p-3 bg-red-100 rounded-full">
              <AlertTriangle className="h-12 w-12 text-red-600" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold text-gray-900">404 - Page Not Found</CardTitle>
          <CardDescription>The page you're looking for doesn't exist or has been moved.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-600">You'll be automatically redirected to the main website in 5 seconds.</p>

          <div className="flex flex-col sm:flex-row gap-2 justify-center">
            <Button asChild variant="default">
              <a href="/">
                <Home className="h-4 w-4 mr-2" />
                Go Home
              </a>
            </Button>
            <Button asChild variant="outline">
              <a href="https://debasisbiswas.me" target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4 mr-2" />
                Visit Main Site
              </a>
            </Button>
          </div>

          <div className="pt-4 border-t border-gray-200">
            <p className="text-xs text-gray-500">Made by Debasis Biswas | forensic@debasisbiswas.me</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
