"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";

interface TerminalLine {
  text: string;
  color?: string;
  delay?: number;
  indent?: number;
}

interface TerminalProps {
  lines: TerminalLine[];
  typingSpeed?: number;
  className?: string;
  startDelay?: number;
  onComplete?: () => void;
}

const COLOR_MAP: Record<string, string> = {
  green: "text-[oklch(0.65_0.2_145)]",
  red: "text-[oklch(0.60_0.15_25)]",
  yellow: "text-[oklch(0.75_0.15_85)]",
  blue: "text-[oklch(0.60_0.15_260)]",
  violet: "text-[oklch(0.60_0.18_280)]",
  cyan: "text-[oklch(0.70_0.12_200)]",
  dim: "text-[oklch(0.50_0.01_262)]",
  white: "text-[oklch(0.90_0.01_262)]",
  bold: "text-[oklch(0.95_0.01_262)] font-bold",
};

export function Terminal({
  lines,
  typingSpeed = 25,
  className = "",
  startDelay = 500,
  onComplete,
}: TerminalProps) {
  const [displayedLines, setDisplayedLines] = useState<string[]>([]);
  const [currentLineIndex, setCurrentLineIndex] = useState(-1);
  const [currentCharIndex, setCurrentCharIndex] = useState(0);
  const [isTyping, setIsTyping] = useState(false);
  const [started, setStarted] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const reducedMotion = useRef(false);

  useEffect(() => {
    reducedMotion.current = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
    if (reducedMotion.current) {
      setDisplayedLines(lines.map((l) => " ".repeat(l.indent || 0) + l.text));
      setCurrentLineIndex(lines.length);
      onComplete?.();
      return;
    }

    const timer = setTimeout(() => {
      setStarted(true);
      setCurrentLineIndex(0);
      setIsTyping(true);
    }, startDelay);

    return () => clearTimeout(timer);
  }, []);

  const advanceLine = useCallback(() => {
    setCurrentLineIndex((prev) => {
      const next = prev + 1;
      if (next >= lines.length) {
        setIsTyping(false);
        onComplete?.();
        return prev;
      }
      setCurrentCharIndex(0);
      return next;
    });
  }, [lines.length, onComplete]);

  useEffect(() => {
    if (!started || currentLineIndex < 0 || currentLineIndex >= lines.length)
      return;

    const line = lines[currentLineIndex];
    const fullText = " ".repeat(line.indent || 0) + line.text;

    if (line.delay && currentCharIndex === 0) {
      const delayTimer = setTimeout(() => {
        setCurrentCharIndex(1);
      }, line.delay);
      return () => clearTimeout(delayTimer);
    }

    const effectiveCharIndex =
      line.delay && currentCharIndex === 0 ? 0 : currentCharIndex;

    if (effectiveCharIndex >= fullText.length) {
      setDisplayedLines((prev) => {
        const newLines = [...prev];
        newLines[currentLineIndex] = fullText;
        return newLines;
      });
      const nextDelay = line.text === "" ? 50 : 80;
      const timer = setTimeout(advanceLine, nextDelay);
      return () => clearTimeout(timer);
    }

    const timer = setTimeout(
      () => {
        setDisplayedLines((prev) => {
          const newLines = [...prev];
          newLines[currentLineIndex] = fullText.slice(
            0,
            effectiveCharIndex + 1
          );
          return newLines;
        });
        setCurrentCharIndex(effectiveCharIndex + 1);
      },
      line.text.startsWith("$") ? typingSpeed * 2 : typingSpeed
    );

    return () => clearTimeout(timer);
  }, [
    started,
    currentLineIndex,
    currentCharIndex,
    lines,
    typingSpeed,
    advanceLine,
  ]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [displayedLines]);

  return (
    <div
      className={`rounded-2xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.15)] ${className}`}
    >
      {/* Title bar */}
      <div className="bg-[oklch(0.18_0.02_262)] px-4 py-3 flex items-center gap-2">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-[oklch(0.60_0.20_25)]" />
          <div className="w-3 h-3 rounded-full bg-[oklch(0.75_0.15_85)]" />
          <div className="w-3 h-3 rounded-full bg-[oklch(0.65_0.20_145)]" />
        </div>
        <span className="text-xs text-[oklch(0.50_0.01_262)] font-mono ml-2">
          smartcrack
        </span>
      </div>

      {/* Terminal body */}
      <div
        ref={containerRef}
        className="bg-terminal-bg p-5 font-mono text-sm leading-relaxed overflow-y-auto max-h-[420px]"
      >
        {displayedLines.map((lineText, i) => {
          const lineDef = lines[i];
          const colorClass = lineDef?.color
            ? COLOR_MAP[lineDef.color] || "text-[oklch(0.85_0.01_262)]"
            : "text-[oklch(0.85_0.01_262)]";

          return (
            <div key={i} className={`${colorClass} whitespace-pre`}>
              {lineText}
              {i === currentLineIndex && isTyping && (
                <span className="cursor-blink text-[oklch(0.65_0.2_145)]">
                  |
                </span>
              )}
            </div>
          );
        })}
        {!isTyping && currentLineIndex >= lines.length && (
          <div className="text-[oklch(0.85_0.01_262)] whitespace-pre mt-1">
            ${" "}
            <span className="cursor-blink text-[oklch(0.65_0.2_145)]">|</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function TerminalSkeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`rounded-2xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.15)] ${className}`}
    >
      <div className="bg-[oklch(0.18_0.02_262)] px-4 py-3 flex items-center gap-2">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-[oklch(0.30_0.02_262)]" />
          <div className="w-3 h-3 rounded-full bg-[oklch(0.30_0.02_262)]" />
          <div className="w-3 h-3 rounded-full bg-[oklch(0.30_0.02_262)]" />
        </div>
      </div>
      <div className="bg-terminal-bg p-5 h-64 relative overflow-hidden shimmer" />
    </div>
  );
}
