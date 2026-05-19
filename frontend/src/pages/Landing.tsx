import { motion } from "framer-motion";
import { ArrowRight, Crosshair, Radar, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";

const features = [
  { title: "Crawler", body: "Recursive link, form, parameter, and login-page discovery.", icon: Crosshair },
  { title: "Detection", body: "SQLi, XSS, security headers, and sensitive path checks.", icon: ShieldCheck },
  { title: "Reporting", body: "JSON and PDF evidence reports with risk scoring.", icon: Radar }
];

export function Landing() {
  return (
    <main className="min-h-screen overflow-hidden bg-grid bg-[size:36px_36px] text-slate-100">
      <div className="scanline" />
      <section className="mx-auto flex min-h-[92vh] max-w-7xl flex-col justify-center px-6 py-12">
        <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="max-w-4xl">
          <div className="mb-6 inline-flex items-center gap-2 rounded-md border border-cyanfire/30 bg-cyanfire/10 px-3 py-2 text-sm text-cyan-100">
            <Radar size={16} /> AI-powered web vulnerability scanning
          </div>
          <h1 className="text-5xl font-black leading-tight text-white md:text-7xl">SentinelAI Security Scanner</h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
            Crawl authorized targets, detect injection flaws and weak headers, stream scan telemetry, and generate polished security reports from one modern operations console.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/login"><Button>Open Console <ArrowRight size={18} /></Button></Link>
            <Link to="/register"><Button className="border-slate-600 bg-slate-900/80">Create Analyst</Button></Link>
          </div>
        </motion.div>
        <div className="mt-12 grid gap-4 md:grid-cols-3">
          {features.map(({ title, body, icon: Icon }) => (
            <Card key={title} className="min-h-36">
              <Icon className="text-cyanfire" />
              <h2 className="mt-4 text-lg font-bold">{title}</h2>
              <p className="mt-2 text-sm text-slate-400">{body}</p>
            </Card>
          ))}
        </div>
      </section>
    </main>
  );
}
