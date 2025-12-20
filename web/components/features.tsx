"use client";

import { motion, useReducedMotion } from "framer-motion";
import {
  Brain,
  Shield,
  Layers,
  FileText,
  Search,
  Puzzle,
} from "lucide-react";
import type { ReactNode } from "react";

interface Feature {
  icon: ReactNode;
  title: string;
  description: string;
}

const FEATURES: Feature[] = [
  {
    icon: <Brain className="w-6 h-6" />,
    title: "Adaptive AI",
    description:
      "Multi-round LLM reasoning that adapts strategy based on failed attempts. Chain-of-thought visible in real time.",
  },
  {
    icon: <Shield className="w-6 h-6" />,
    title: "Real Hash Support",
    description:
      "bcrypt, argon2, NTLM, SHA-256, and more. Auto-identification with confidence scoring before cracking begins.",
  },
  {
    icon: <Layers className="w-6 h-6" />,
    title: "Batch Processing",
    description:
      "Crack thousands of hashes with a live TUI dashboard showing real-time analytics and progress tracking.",
  },
  {
    icon: <FileText className="w-6 h-6" />,
    title: "Security Audits",
    description:
      "Generate professional Markdown and HTML audit reports documenting methodology, findings, and recommendations.",
  },
  {
    icon: <Search className="w-6 h-6" />,
    title: "OSINT Automation",
    description:
      "Give a username, get a full target profile. Automated platform enumeration feeds directly into attack planning.",
  },
  {
    icon: <Puzzle className="w-6 h-6" />,
    title: "Plugin System",
    description:
      "Extensible architecture with hashcat .rule file compatibility. Bring your own wordlists, rules, and strategies.",
  },
];

function FeatureCard({
  feature,
  index,
}: {
  feature: Feature;
  index: number;
}) {
  const reducedMotion = useReducedMotion();

  return (
    <motion.div
      initial={reducedMotion ? undefined : { opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{
        type: "spring",
        stiffness: 300,
        damping: 30,
        mass: 0.8,
        delay: index * 0.05,
      }}
      whileHover={
        reducedMotion
          ? undefined
          : { y: -2, boxShadow: "0 16px 48px rgba(0,0,0,0.08)" }
      }
      className="glass-card rounded-2xl p-6 cursor-default
        shadow-[0_2px_12px_rgba(0,0,0,0.04)] transition-shadow"
    >
      <div
        className="w-10 h-10 rounded-xl flex items-center justify-center mb-4
          bg-accent/10 text-accent"
      >
        {feature.icon}
      </div>
      <h3 className="text-base font-semibold text-text-primary mb-2">
        {feature.title}
      </h3>
      <p className="text-sm text-text-secondary leading-relaxed">
        {feature.description}
      </p>
    </motion.div>
  );
}

export function Features() {
  return (
    <section className="py-32 relative">
      <div className="mx-auto max-w-[1280px] px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.2, 0.8, 0.2, 1] }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl sm:text-4xl font-bold text-text-primary mb-4">
            Everything you need to{" "}
            <span className="gradient-text">crack hashes</span>
          </h2>
          <p className="text-lg text-text-secondary max-w-2xl mx-auto">
            From dictionary attacks to adaptive AI reasoning, HashCrack
            orchestrates the entire workflow in a single command.
          </p>
        </motion.div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map((feature, i) => (
            <FeatureCard key={feature.title} feature={feature} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
