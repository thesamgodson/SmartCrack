"use client";

import { motion, useReducedMotion } from "framer-motion";

interface ArchNode {
  label: string;
  sublabel?: string;
  color: "accent" | "surface" | "success";
}

const PIPELINE: ArchNode[][] = [
  [{ label: "CLI Input", sublabel: "hash + target", color: "surface" }],
  [
    { label: "Hash ID", sublabel: "auto-detect", color: "surface" },
    { label: "OSINT", sublabel: "profile build", color: "surface" },
  ],
  [{ label: "Attack Planner", sublabel: "5-phase strategy", color: "accent" }],
  [
    { label: "Dictionary", color: "surface" },
    { label: "Rules", color: "surface" },
    { label: "AI Profiler", color: "accent" },
    { label: "Adaptive", color: "accent" },
  ],
  [{ label: "Cracker", sublabel: "orchestrator", color: "accent" }],
  [{ label: "Analysis", sublabel: "results + metrics", color: "surface" }],
  [{ label: "Report", sublabel: "MD / HTML", color: "success" }],
];

const NODE_COLORS = {
  accent: "bg-accent/10 border-accent/20 text-accent",
  surface:
    "bg-text-primary/5 border-text-primary/10 text-text-primary",
  success:
    "bg-[oklch(0.65_0.2_145)]/10 border-[oklch(0.65_0.2_145)]/20 text-[oklch(0.55_0.2_145)]",
};

function PipelineNode({
  node,
  rowIndex,
  nodeIndex,
}: {
  node: ArchNode;
  rowIndex: number;
  nodeIndex: number;
}) {
  const reducedMotion = useReducedMotion();
  const delay = rowIndex * 0.08 + nodeIndex * 0.03;

  return (
    <motion.div
      initial={reducedMotion ? undefined : { opacity: 0, scale: 0.9 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      transition={{
        type: "spring",
        stiffness: 300,
        damping: 30,
        delay,
      }}
      className={`px-4 py-2.5 rounded-xl border text-center min-w-[100px]
        ${NODE_COLORS[node.color]}`}
    >
      <div className="text-sm font-medium">{node.label}</div>
      {node.sublabel && (
        <div className="text-xs opacity-60 mt-0.5">{node.sublabel}</div>
      )}
    </motion.div>
  );
}

function ConnectorArrow({ rowIndex }: { rowIndex: number }) {
  const reducedMotion = useReducedMotion();

  return (
    <motion.div
      initial={reducedMotion ? undefined : { opacity: 0 }}
      whileInView={{ opacity: 0.3 }}
      viewport={{ once: true }}
      transition={{ delay: rowIndex * 0.08 + 0.1 }}
      className="flex justify-center py-2"
    >
      <svg
        width="2"
        height="24"
        viewBox="0 0 2 24"
        className="text-text-secondary"
      >
        <line
          x1="1"
          y1="0"
          x2="1"
          y2="18"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeDasharray="3 3"
        />
        <polygon points="0,18 1,24 2,18" fill="currentColor" />
      </svg>
    </motion.div>
  );
}

export function Architecture() {
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
            How it works
          </h2>
          <p className="text-lg text-text-secondary max-w-2xl mx-auto">
            A multi-phase pipeline that adapts in real time. Each stage feeds
            intelligence to the next.
          </p>
        </motion.div>

        <div className="max-w-3xl mx-auto flex flex-col items-center">
          {PIPELINE.map((row, rowIndex) => (
            <div key={rowIndex}>
              {rowIndex > 0 && <ConnectorArrow rowIndex={rowIndex} />}
              <div className="flex flex-wrap items-center justify-center gap-3">
                {row.map((node, nodeIndex) => (
                  <PipelineNode
                    key={node.label}
                    node={node}
                    rowIndex={rowIndex}
                    nodeIndex={nodeIndex}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
