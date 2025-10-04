import React from "react";

export default function PrivacyPolicyPage() {
  return (
    <main className="max-w-2xl mx-auto py-12 px-4">
      <h1 className="text-3xl font-bold mb-6">Privacy Policy</h1>
      <p className="mb-4">
        We value your privacy and are committed to protecting your information. This Privacy Policy explains what data we collect and how we use it.
      </p>
      <h2 className="text-xl font-semibold mt-6 mb-2">Information We Collect</h2>
      <ul className="list-disc list-inside mb-4">
        <li>User IP address</li>
        <li>Device and browser information</li>
        <li>Search time and date</li>
        <li>What was searched (URL or domain)</li>
      </ul>
      <h2 className="text-xl font-semibold mt-6 mb-2">Purpose of Data Collection</h2>
      <p className="mb-4">
        We collect this information solely for security purposes, such as detecting and preventing abuse, fraud, and phishing attempts. No data is shared with any third party.
      </p>
      <h2 className="text-xl font-semibold mt-6 mb-2">Data Sharing</h2>
      <p className="mb-4">
        We do <strong>not</strong> share, sell, or disclose your data to any third party. All collected data is used internally for security analysis only.
      </p>
      <h2 className="text-xl font-semibold mt-6 mb-2">Contact</h2>
      <p>
        If you have any questions about this Privacy Policy, please contact us at forensic@debasisbiswas.me.
      </p>
    </main>
  );
}
