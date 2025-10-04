
import React from "react";

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen w-full bg-gradient-to-br from-blue-50 via-purple-100 to-pink-50 animate-gradient-x flex items-center justify-center relative overflow-hidden">
      {/* Animated background blobs */}
      <div className="absolute top-0 left-0 w-80 h-80 bg-blue-200 rounded-full mix-blend-multiply filter blur-2xl opacity-40 animate-blob1" />
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-pink-200 rounded-full mix-blend-multiply filter blur-2xl opacity-40 animate-blob2" />
      <div className="absolute top-1/2 left-1/2 w-72 h-72 bg-purple-200 rounded-full mix-blend-multiply filter blur-2xl opacity-30 animate-blob3" />
      <main className="relative z-10 max-w-2xl mx-auto py-12 px-4 bg-white/80 rounded-xl shadow-xl backdrop-blur-md">
        <h1 className="text-3xl font-bold mb-6 text-purple-700">Privacy Policy</h1>
        <p className="mb-4 text-gray-700">
          We value your privacy and are committed to protecting your information. This Privacy Policy explains what data we collect and how we use it.
        </p>
        <h2 className="text-xl font-semibold mt-6 mb-2 text-blue-700">Information We Collect</h2>
        <ul className="list-disc list-inside mb-4 text-gray-800">
          <li>User IP address</li>
          <li>ISP (Internet Service Provider)</li>
          <li>IP-based location (approximate geolocation)</li>
          <li>Device and browser information</li>
          <li>Search time and date</li>
          <li>What was searched (URL or domain)</li>
        </ul>
        <h2 className="text-xl font-semibold mt-6 mb-2 text-blue-700">Purpose of Data Collection</h2>
        <p className="mb-4 text-gray-700">
          We collect this information solely for security purposes, such as detecting and preventing abuse, fraud, and phishing attempts. No data is shared with any third party.
        </p>
        <h2 className="text-xl font-semibold mt-6 mb-2 text-blue-700">Data Sharing</h2>
        <p className="mb-4 text-gray-700">
          We do <strong>not</strong> share, sell, or disclose your data to any third party. All collected data is used internally for security analysis only.
        </p>
        <h2 className="text-xl font-semibold mt-6 mb-2 text-blue-700">Contact</h2>
        <p className="text-gray-700">
          If you have any questions about this Privacy Policy, please contact us at forensic@debasisbiswas.me.
        </p>
      </main>
      <style jsx global>{`
        @keyframes gradient-x {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }
        .animate-gradient-x {
          background-size: 200% 200%;
          animation: gradient-x 8s ease-in-out infinite;
        }
        @keyframes blob1 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(30px, -20px) scale(1.1); }
          66% { transform: translate(-20px, 30px) scale(0.9); }
        }
        .animate-blob1 { animation: blob1 12s infinite linear; }
        @keyframes blob2 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(-40px, 20px) scale(1.05); }
          66% { transform: translate(20px, -30px) scale(0.95); }
        }
        .animate-blob2 { animation: blob2 14s infinite linear; }
        @keyframes blob3 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(10px, 10px) scale(1.08); }
          66% { transform: translate(-10px, -10px) scale(0.92); }
        }
        .animate-blob3 { animation: blob3 16s infinite linear; }
      `}</style>
    </div>
  );
}
