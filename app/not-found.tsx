"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"

export default function NotFound() {
  const [parallax, setParallax] = useState({ x: 0, y: 0 })

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const x = (window.innerWidth / 2 - e.clientX) * 0.03
      const y = (window.innerHeight / 2 - e.clientY) * 0.03
      setParallax({ x, y })
    }
    window.addEventListener("mousemove", handler)
    return () => window.removeEventListener("mousemove", handler)
  }, [])

  useEffect(() => {
    const container = document.getElementById("stars")
    if (!container) return

    for (let i = 0; i < 70; i++) {
      const star = document.createElement("div")
      star.className = "star"
      star.style.top = Math.random() * 100 + "%"
      star.style.left = Math.random() * 100 + "%"
      star.style.animationDuration = 1 + Math.random() * 2 + "s"
      container.appendChild(star)
    }
  }, [])

  return (
    <div className="relative min-h-screen bg-[#080d1f] text-white overflow-hidden flex flex-col items-center justify-center text-center">
      <div id="stars" className="absolute inset-0"></div>

      <div className="absolute text-5xl animate-bounce left-10 top-10">🛸</div>
      <div className="absolute text-5xl animate-float right-16 bottom-16">👽</div>
      <div className="absolute text-6xl animate-float-slow left-1/4 bottom-20">🚀</div>

      <h1 className="text-6xl font-bold mt-20 animate-glow">404</h1>

      <p className="msg">
        <strong>Congratulations!</strong><br />
        You’ve officially discovered a page that doesn’t exist.<br />
        Even our astronaut is confused… and he's literally floating in space.
      </p>

      <img
        className="astronaut"
        style={{ transform: `translate(${parallax.x}px, ${parallax.y}px)` }}
        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNTMxIiBoZWlnaHQ9IjUzMSIgdmlld0JveD0iMCAwIDUzMSA1MzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbD0iI2ZmZiIgZD0iTTI2NS41IDQwOGMtNzguNCAwLTE0Mi41LTY0LjEtMTQyLjUtMTQyLjVTMTg3LjEgMTIzIDI2NS41IDEyM2M3OC40IDAgMTQyLjUgNjQuMSAxNDIuNSAxNDIuNXMtNjQuMSAxNDIuNS0xNDIuNSAxNDIuNXptMCAyMThjMTEzLjMgMCAyMDUtOTEuNyAyMDUtMjA1cy05MS43LTIwNS0yMDUtMjA1LTIwNSA5MS43LTIwNSAyMDUgOTEuNyAyMDUgMjA1IDIwNXoiLz48L3N2Zz4="
        alt="Astronaut"
      />

      <img
        className="planet"
        style={{ transform: `translate(${parallax.x * 0.5}px, ${parallax.y * 0.5}px)` }}
        src="data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9IjQwMCIgd2lkdGg9IjQwMCIgdmlld0JveD0iMCAwIDUwMCA1MDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBmaWxsPSIjMzlhMGZmIiBjeD0iMjUwIiBjeT0iMjUwIiByPSIyMDAiLz48L3N2Zz4="
        alt="Planet"
      />

      <Button asChild className="btn mt-10 z-10">
        <a href="/">Go Back Home</a>
      </Button>

      <style jsx global>{`
        body { margin: 0; }

        .star {
          position: absolute;
          width: 3px;
          height: 3px;
          background: white;
          border-radius: 50%;
          animation: twinkle 2s infinite alternate;
        }

        @keyframes twinkle {
          from { opacity: 0.3; }
          to { opacity: 1; }
        }

        .animate-glow {
          text-shadow: 0 0 20px #fff, 0 0 40px #0ff;
          animation: glow 2s infinite alternate;
        }

        @keyframes glow {
          from { text-shadow: 0 0 10px #0ff; }
          to { text-shadow: 0 0 30px #0ff; }
        }

        .astronaut {
          width: 150px;
          position: absolute;
          top: 140px;
          left: 50px;
          animation: floaty 6s infinite ease-in-out;
        }

        @keyframes floaty {
          0% { transform: translate(-50px, 0px) rotate(-6deg); }
          50% { transform: translate(50px, -40px) rotate(6deg); }
          100% { transform: translate(-50px, 0px) rotate(-6deg); }
        }

        .planet {
          position: absolute;
          bottom: -30px;
          right: -60px;
          width: 300px;
          animation: slowspin 20s infinite linear;
        }

        @keyframes slowspin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .btn {
          background: #ff005d !important;
          color: white;
          padding: 15px 30px;
          border-radius: 12px;
          box-shadow: 0 0 15px #ff005daa;
          transition: 0.2s;
          font-size: 1.2rem;
        }

        .btn:hover {
          background: #ff3380 !important;
          transform: translateY(-3px);
        }

        .msg {
          font-size: 1.4rem;
          opacity: 0.9;
          max-width: 600px;
          margin: 20px auto;
          line-height: 1.5;
        }

        .animate-float {
          animation: float 4s ease-in-out infinite;
        }

        .animate-float-slow {
          animation: float 7s ease-in-out infinite;
        }

        @keyframes float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-20px); }
        }
      `}</style>
    </div>
  )
}
