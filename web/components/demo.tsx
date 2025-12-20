"use client";

import { motion, useInView, useReducedMotion } from "framer-motion";
import { useRef, useState } from "react";
import { Terminal } from "./terminal";

const DEMO_LINES = [
  {
    text: '$ hashcrack smart -H "5d41402abc4b2a76b9719d911017c592" --osint-target @johndoe',
    color: "white" as const,
    delay: 300,
  },
  { text: "", color: "dim" as const },
  { text: "Enumerating username: johndoe", color: "cyan" as const, delay: 200 },
  {
    text: "github         FOUND  https://github.com/johndoe",
    color: "green" as const,
    indent: 2,
    delay: 150,
  },
  {
    text: "twitter        FOUND  https://x.com/johndoe",
    color: "green" as const,
    indent: 2,
    delay: 100,
  },
  {
    text: "instagram      not found",
    color: "dim" as const,
    indent: 2,
    delay: 100,
  },
  {
    text: "linkedin       FOUND  https://linkedin.com/in/johndoe",
    color: "green" as const,
    indent: 2,
    delay: 100,
  },
  { text: "", color: "dim" as const },
  {
    text: "Building target profile from 3 sources...",
    color: "cyan" as const,
    delay: 300,
  },
  { text: "", color: "dim" as const },
  { text: "[1/5] Dictionary", color: "yellow" as const, delay: 200 },
  { text: "[2/5] Dictionary + Quick Rules", color: "yellow" as const, delay: 150 },
  { text: "[3/5] Profile", color: "yellow" as const, delay: 150 },
  { text: "[4/5] Profile + Quick Rules", color: "yellow" as const, delay: 150 },
  { text: "[5/5] Adaptive AI", color: "violet" as const, delay: 200 },
  {
    text: "Round 1: Analyzing target profile... name+date patterns",
    color: "dim" as const,
    indent: 2,
    delay: 200,
  },
  {
    text: "Generated 247 candidates",
    color: "cyan" as const,
    indent: 4,
    delay: 150,
  },
  {
    text: "Round 2: Trying technical patterns, keyboard walks",
    color: "dim" as const,
    indent: 2,
    delay: 200,
  },
  {
    text: "Generated 183 candidates",
    color: "cyan" as const,
    indent: 4,
    delay: 150,
  },
  { text: "", color: "dim" as const },
  { text: "[+] Cracked: hello", color: "green" as const, delay: 500 },
  { text: "[+] Algorithm: MD5", color: "green" as const },
  { text: "[+] Phase: adaptive", color: "green" as const },
  { text: "[+] Attempts: 142,847", color: "green" as const },
  { text: "[+] Time: 3.21s", color: "green" as const },
  { text: "", color: "dim" as const },
  {
    text: "Report saved: ./reports/audit-2024-03-15.html",
    color: "cyan" as const,
    delay: 200,
  },
];

export function Demo() {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-100px" });
  const reducedMotion = useReducedMotion();
  const [hasStarted, setHasStarted] = useState(false);

  if (isInView && !hasStarted) {
    setHasStarted(true);
  }

  return (
    <section id="demo" className="py-32 relative">
      <div className="mx-auto max-w-[1280px] px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.2, 0.8, 0.2, 1] }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl sm:text-4xl font-bold text-text-primary mb-4">
            See it in action
          </h2>
          <p className="text-lg text-text-secondary max-w-2xl mx-auto">
            One command. Recon, profiling, multi-phase cracking, and a full
            audit report. Watch the entire workflow unfold.
          </p>
        </motion.div>

        <motion.div
          ref={ref}
          initial={reducedMotion ? undefined : { opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, ease: [0.2, 0.8, 0.2, 1] }}
          className="max-w-4xl mx-auto"
        >
          {hasStarted && (
            <Terminal
              lines={DEMO_LINES}
              typingSpeed={15}
              startDelay={400}
              className="shadow-[0_16px_64px_rgba(124,58,237,0.12)]"
            />
          )}
        </motion.div>
      </div>
    </section>
  );
}
