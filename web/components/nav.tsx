"use client";

import { motion } from "framer-motion";
import { Terminal } from "lucide-react";
import { GitHubIcon } from "./icons";
import { ThemeToggle } from "./theme-toggle";

const GITHUB_URL = "https://github.com/sam/smartcrack";

export function Nav() {
  return (
    <motion.nav
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.2, 0.8, 0.2, 1] }}
      className="fixed top-0 left-0 right-0 z-50 glass-card"
    >
      <div className="mx-auto max-w-[1280px] px-6 h-16 flex items-center justify-between">
        <a href="#" className="flex items-center gap-2 group">
          <div className="w-8 h-8 rounded-lg gradient-btn flex items-center justify-center">
            <Terminal className="w-4 h-4 text-white" />
          </div>
          <span className="text-lg font-semibold text-text-primary tracking-tight">
            SmartCrack
          </span>
        </a>

        <div className="flex items-center gap-3">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm
              text-text-secondary hover:text-text-primary hover:bg-text-primary/5
              transition-colors"
          >
            <GitHubIcon className="w-4 h-4" />
            <span className="hidden sm:inline">GitHub</span>
          </a>
          <ThemeToggle />
        </div>
      </div>
    </motion.nav>
  );
}
