import { Loader2, Shield } from "lucide-react"

export default function Loading() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
      <div className="text-center">
        <div className="flex justify-center mb-4">
          <div className="p-3 bg-blue-600 rounded-full animate-pulse">
            <Shield className="h-8 w-8 text-white" />
          </div>
        </div>
        <div className="flex items-center justify-center gap-2 text-blue-600">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-lg font-medium">Loading Security Scanner...</span>
        </div>
      </div>
    </div>
  )
}
