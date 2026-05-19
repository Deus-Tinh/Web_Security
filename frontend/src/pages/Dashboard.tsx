import { FormEvent, useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { motion } from "framer-motion";
import { AlertTriangle, Bug, Play, Radar, ShieldCheck } from "lucide-react";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Input } from "../components/ui/Input";
import { createScan, getStats } from "../services/api";
import type { DashboardStats } from "../types/api";

const statCards = [
  { label: "Total scans", key: "total", icon: Radar },
  { label: "Vulnerabilities", key: "vulns", icon: Bug },
  { label: "Active scans", key: "active", icon: ShieldCheck },
  { label: "Risk score", key: "risk", icon: AlertTriangle }
];

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    getStats().then(setStats).catch(() => toast.error("Could not load dashboard")).finally(() => setLoading(false));
  }, []);

  const severityData = useMemo(() => [
    { name: "Critical", value: 3 },
    { name: "High", value: 7 },
    { name: "Medium", value: 12 },
    { name: "Low", value: 18 }
  ], []);
  const trendData = useMemo(() => ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((day, index) => ({ day, scans: index + 2, risk: 20 + index * 9 })), []);

  async function onScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = String(new FormData(event.currentTarget).get("target"));
    try {
      const scan = await createScan(target);
      toast.success(`Scan #${scan.id} queued`);
    } catch {
      toast.error("Scan rejected. Check target scope and authentication.");
    }
  }

  if (loading) return <div className="h-64 animate-pulse rounded-lg bg-slate-900" />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div>
          <p className="text-sm uppercase tracking-widest text-cyanfire">Command Center</p>
          <h1 className="mt-2 text-3xl font-black text-white">Security Dashboard</h1>
        </div>
        <form className="flex w-full max-w-2xl gap-2" onSubmit={onScan}>
          <Input name="target" placeholder="http://localhost:5000/search?q=test" required />
          <Button><Play size={16} /> Launch</Button>
        </form>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {statCards.map(({ label, key, icon: Icon }, index) => {
          const value =
            key === "total" ? stats?.total_scans ?? 0 :
            key === "vulns" ? stats?.vulnerabilities ?? 0 :
            key === "active" ? stats?.active_scans ?? 0 :
            Math.max(...(stats?.recent.map((s) => s.risk_score) || [0]));
          return (
          <motion.div key={label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.06 }}>
            <Card>
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">{label}</p>
                <Icon className="text-cyanfire" size={20} />
              </div>
              <p className="mt-4 text-3xl font-black">{value}</p>
            </Card>
          </motion.div>
        )})}
      </div>
      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <h2 className="font-bold">Scan Trend</h2>
          <div className="mt-4 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs><linearGradient id="risk" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#42e8f6" stopOpacity={0.45} /><stop offset="95%" stopColor="#42e8f6" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid stroke="#1f2937" />
                <XAxis dataKey="day" stroke="#94a3b8" /><YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ background: "#0d1421", border: "1px solid #243447" }} />
                <Area type="monotone" dataKey="risk" stroke="#42e8f6" fill="url(#risk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card className="xl:col-span-2">
          <h2 className="font-bold">Severity Distribution</h2>
          <div className="mt-4 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid stroke="#1f2937" />
                <XAxis dataKey="name" stroke="#94a3b8" /><YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ background: "#0d1421", border: "1px solid #243447" }} />
                <Bar dataKey="value" fill="#a3ff12" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
      <Card>
        <h2 className="font-bold">Recent Activity</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-slate-400"><tr><th className="py-3">Target</th><th>Status</th><th>Progress</th><th>Risk</th></tr></thead>
            <tbody>
              {stats?.recent.length ? stats.recent.map((scan) => (
                <tr key={scan.id} className="border-t border-slate-800">
                  <td className="py-3 text-cyan-100">{scan.target_url}</td><td>{scan.status}</td><td>{scan.progress}%</td><td>{scan.risk_score}</td>
                </tr>
              )) : <tr><td className="py-6 text-slate-400" colSpan={4}>No scans yet. Launch one against an authorized lab target.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
