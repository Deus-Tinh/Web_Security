import { clsx } from "clsx";
import type { Severity } from "../types/api";

const colors: Record<Severity, string> = {
  critical: "border-danger/40 bg-danger/15 text-rose-200",
  high: "border-orange-400/40 bg-orange-500/15 text-orange-200",
  medium: "border-yellow-300/40 bg-yellow-500/15 text-yellow-100",
  low: "border-cyanfire/40 bg-cyanfire/10 text-cyan-100",
  info: "border-slate-400/30 bg-slate-500/10 text-slate-200"
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={clsx("rounded-md border px-2 py-1 text-xs font-semibold uppercase", colors[severity])}>{severity}</span>;
}

