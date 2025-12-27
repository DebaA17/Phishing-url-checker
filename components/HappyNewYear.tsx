"use client";
import React, { useEffect, useState } from 'react';

const Confetti = () => {
  useEffect(() => {
    const canvas = document.getElementById('confetti-canvas') as HTMLCanvasElement | null;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = window.innerWidth;
    const H = window.innerHeight;
    canvas.width = W;
    canvas.height = H;

    const confettiCount = 150;
    const confettiColors = ['#FFD700', '#FF69B4', '#00BFFF', '#32CD32', '#FF4500'];
    const confetti = Array.from({ length: confettiCount }).map(() => ({
      x: Math.random() * W,
      y: Math.random() * H - H,
      r: Math.random() * 6 + 4,
      d: Math.random() * confettiCount,
      color: confettiColors[Math.floor(Math.random() * confettiColors.length)],
      tilt: Math.floor(Math.random() * 10) - 10,
      tiltAngleIncremental: (Math.random() * 0.07) + .05,
      tiltAngle: 0
    }));

    function draw() {
      if (!ctx) return;
      ctx.clearRect(0, 0, W, H);
      confetti.forEach(c => {
        ctx.beginPath();
        ctx.lineWidth = c.r;
        ctx.strokeStyle = c.color;
        ctx.moveTo(c.x + c.tilt + (c.r / 3), c.y);
        ctx.lineTo(c.x + c.tilt, c.y + c.tilt + c.r);
        ctx.stroke();
      });
      update();
    }

    function update() {
      confetti.forEach((c, i) => {
        c.y += (Math.cos(c.d) + 3 + c.r / 2) / 2;
        c.x += Math.sin(0.01 * c.d);
        c.tiltAngle += c.tiltAngleIncremental;
        c.tilt = Math.sin(c.tiltAngle - (i % 3)) * 15;
        if (c.y > H) {
          confetti[i] = {
            ...c,
            x: Math.random() * W,
            y: -10,
            tilt: Math.floor(Math.random() * 10) - 10
          };
        }
      });
    }

    let animationFrameId: number;
    function animate() {
      draw();
      animationFrameId = requestAnimationFrame(animate);
    }
    animate();
    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  return (
    <canvas id="confetti-canvas" style={{position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', pointerEvents: 'none', zIndex: 9999}} />
  );
};

const isNewYear = () => {
  const now = new Date();
  const month = now.getMonth(); // 0-indexed
  const date = now.getDate();
  // January 1st only
  return month === 0 && date === 1;
};

const HappyNewYear = () => {
  const [show, setShow] = useState(false);
  const [fade, setFade] = useState(false);
  const nextYear = new Date().getFullYear() + 1;
  useEffect(() => {
    if (isNewYear()) {
      setShow(true);
      setTimeout(() => {
        setFade(true);
        setTimeout(() => setShow(false), 1000); // 1s for fade-out
      }, 4000); // 4 seconds visible
    }
  }, []);
  if (!show) return null;
  return (
    <div
      style={{
        position: 'fixed',
        left: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 9998,
        display: 'flex',
        alignItems: 'flex-end',
        justifyContent: 'center',
        pointerEvents: 'none',
        opacity: fade ? 0 : 1,
        transition: 'opacity 1s ease',
      }}
    >
      <Confetti />
      <div
        style={{
          fontSize: '3rem',
          color: '#FFD700',
          textShadow: '2px 2px 8px #000',
          fontWeight: 'bold',
          pointerEvents: 'none',
          opacity: fade ? 0 : 1,
          transition: 'opacity 1s ease, transform 2.5s cubic-bezier(0.22, 1, 0.36, 1)',
          transform: fade
            ? 'translateY(100vh)'
            : 'translateY(0)', // Start from below the footer
          marginBottom: '40px', // a bit above the bottom
        }}
      >
        🎉 Happy New Year {nextYear}! 🎉
      </div>
    </div>
  );
};

export default HappyNewYear;
