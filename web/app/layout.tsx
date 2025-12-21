import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SmartCrack - AI-Powered Hash Cracking CLI",
  description:
    "Crack smarter, not harder. AI-powered hash cracking with adaptive profiling, OSINT automation, and professional security audit reports.",
  keywords: [
    "hash cracking",
    "security testing",
    "AI",
    "OSINT",
    "penetration testing",
    "CLI tool",
    "Python",
  ],
  openGraph: {
    title: "SmartCrack - AI-Powered Hash Cracking CLI",
    description:
      "Crack smarter, not harder. AI-powered hash cracking with adaptive profiling, OSINT automation, and professional security audit reports.",
    type: "website",
    siteName: "SmartCrack",
  },
  twitter: {
    card: "summary_large_image",
    title: "SmartCrack - AI-Powered Hash Cracking CLI",
    description:
      "Crack smarter, not harder. AI-powered hash cracking with adaptive profiling, OSINT automation, and professional security audit reports.",
  },
};

const themeScript = `(function(){try{var t=localStorage.getItem('theme');if(t==='dark'||(t!=='light'&&window.matchMedia('(prefers-color-scheme:dark)').matches)){document.documentElement.setAttribute('data-theme','dark')}}catch(e){}})()`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
