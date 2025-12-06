"use client";

import { useEffect, useState } from "react";
import { Sun, Moon } from "lucide-react";
import { motion } from "framer-motion";

export function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const current = document.documentElement.getAttribute("data-theme");
    if (current === "dark") setTheme("dark");
  }, []);

  function toggle() {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
  }

  if (!mounted) {
    return <div className="w-9 h-9" />;
  }

  return (
    <motion.button
      onClick={toggle}
      className="relative w-9 h-9 flex items-center justify-center rounded-xl
        bg-text-primary/5 hover:bg-text-primary/10 transition-colors"
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
    >
      {theme === "light" ? (
        <Moon className="w-[18px] h-[18px] text-text-secondary" />
      ) : (
        <Sun className="w-[18px] h-[18px] text-text-secondary" />
      )}
    </motion.button>
  );
}
