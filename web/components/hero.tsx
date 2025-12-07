"use client";

import { motion, useReducedMotion } from "framer-motion";
import { ArrowRight, Play } from "lucide-react";
import dynamic from "next/dynamic";
import { Suspense } from "react";
import { Terminal } from "./terminal";

const Scene3D = dynamic(
  () => import("./scene-3d").then((mod) => ({ default: mod.Scene3D })),
  { ssr: false }
);

const EASING = [0.2, 0.8, 0.2, 1] as const;

const HERO_TERMINAL_LINES = [
  { text: "$ pip install hashcrack", color: "white", delay: 300 },
  { text: "$ hashcrack smart -H '5d41402abc4b2a76b9719d911017c592'", color: "white", delay: 200 },
  { text: "", color: "dim" },
  { text: "Identifying hash... MD5 (confidence: 98%)", color: "cyan" },
  { text: "[1/5] Dictionary attack...", color: "dim", delay: 100 },
  { text: "[+] Cracked: hello", color: "green", delay: 400 },
  { text: "[+] Time: 0.03s", color: "green" },
];

const GITHUB_URL = "https://github.com/sam/hashcrack";

export function Hero() {
  const reducedMotion = useReducedMotion();

  const fadeUp = reducedMotion
    ? {}
    : {
        initial: { opacity: 0, y: 24 },
        animate: { opacity: 1, y: 0 },
      };

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden pt-16">
      {/* Mesh gradient background */}
      {!reducedMotion && (
        <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
          <div
            className="mesh-gradient-orb absolute w-[600px] h-[600px] rounded-full opacity-30 -top-40 -left-40"
            style={{ background: "oklch(0.75 0.15 270)" }}
          />
          <div
            className="mesh-gradient-orb absolute w-[500px] h-[500px] rounded-full opacity-20 top-1/3 right-0"
            style={{
              background: "oklch(0.70 0.12 290)",
              animationDelay: "-3s",
            }}
          />
          <div
            className="mesh-gradient-orb absolute w-[400px] h-[400px] rounded-full opacity-15 bottom-0 left-1/3"
            style={{
              background: "oklch(0.65 0.10 145)",
              animationDelay: "-5s",
            }}
          />
        </div>
      )}

      <div className="relative z-10 mx-auto max-w-[1280px] px-6 py-24 w-full">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left: Copy */}
          <div className="space-y-8">
            <motion.div
              {...fadeUp}
              transition={{ duration: 0.6, ease: EASING, delay: 0.1 }}
            >
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full
                bg-accent/10 text-accent text-xs font-medium tracking-wide mb-6">
                <span className="w-1.5 h-1.5 rounded-full bg-[oklch(0.65_0.2_145)] animate-pulse" />
                293 tests passing
              </div>
            </motion.div>

            <motion.h1
              {...fadeUp}
              transition={{ duration: 0.6, ease: EASING, delay: 0.2 }}
              className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-text-primary"
            >
              Crack Smarter,
              <br />
              <span className="gradient-text">Not Harder</span>
            </motion.h1>

            <motion.p
              {...fadeUp}
              transition={{ duration: 0.6, ease: EASING, delay: 0.3 }}
              className="text-lg sm:text-xl text-text-secondary max-w-lg leading-relaxed"
            >
              AI-powered hash cracking CLI with adaptive profiling, OSINT
              automation, and multi-phase attack orchestration. One command does
              everything.
            </motion.p>

            <motion.div
              {...fadeUp}
              transition={{ duration: 0.6, ease: EASING, delay: 0.4 }}
              className="flex flex-wrap gap-4"
            >
              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="gradient-btn inline-flex items-center gap-2 px-6 py-3 rounded-xl
                  text-white font-medium text-sm shadow-[0_4px_16px_rgba(124,58,237,0.3)]"
              >
                Get Started
                <ArrowRight className="w-4 h-4" />
              </a>
              <a
                href="#demo"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl
                  text-text-primary font-medium text-sm
                  bg-text-primary/5 hover:bg-text-primary/10 transition-colors"
              >
                <Play className="w-4 h-4" />
                View Demo
              </a>
            </motion.div>

            {/* Quick install */}
            <motion.div
              {...fadeUp}
              transition={{ duration: 0.6, ease: EASING, delay: 0.5 }}
              className="flex items-center gap-3"
            >
              <code className="text-sm font-mono px-4 py-2 rounded-lg bg-terminal-bg text-[oklch(0.85_0.01_262)]">
                pip install hashcrack
              </code>
            </motion.div>
          </div>

          {/* Right: 3D + Terminal */}
          <motion.div
            {...fadeUp}
            transition={{ duration: 0.8, ease: EASING, delay: 0.4 }}
            className="relative"
          >
            {/* 3D accent */}
            <div className="absolute -top-16 -right-8 z-0 hidden lg:block">
              <Suspense fallback={null}>
                <Scene3D className="w-[280px] h-[280px]" />
              </Suspense>
            </div>

            <div className="relative z-10">
              <Terminal
                lines={HERO_TERMINAL_LINES}
                typingSpeed={20}
                startDelay={800}
              />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
