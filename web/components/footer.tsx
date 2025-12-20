"use client";

import { motion } from "framer-motion";
import { Terminal } from "lucide-react";
import { GitHubIcon } from "./icons";

const GITHUB_URL = "https://github.com/sam/hashcrack";

export function Footer() {
  return (
    <footer className="py-16 border-t border-text-primary/5">
      <div className="mx-auto max-w-[1280px] px-6">
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="flex flex-col sm:flex-row items-center justify-between gap-6"
        >
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg gradient-btn flex items-center justify-center">
                <Terminal className="w-3.5 h-3.5 text-white" />
              </div>
              <span className="text-sm font-semibold text-text-primary">
                HashCrack
              </span>
            </div>
            <span className="text-xs text-text-secondary">
              Built for authorized security testing only
            </span>
          </div>

          <div className="flex items-center gap-6">
            <span className="text-xs text-text-secondary">
              Made with Python + AI
            </span>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-text-secondary
                hover:text-text-primary transition-colors"
            >
              <GitHubIcon className="w-3.5 h-3.5" />
              GitHub
            </a>
          </div>
        </motion.div>
      </div>
    </footer>
  );
}
