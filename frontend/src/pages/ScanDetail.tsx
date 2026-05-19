import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card } from "../components/ui/Card";
import { SeverityBadge } from "../components/SeverityBadge";
import { getLogs, getScan, getVulnerabilities } from "../services/api";
import type { Scan, Vulnerability } from "../types/api";

export function ScanDetail() {
  const { id = "" } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  useEffect(() => {
    getScan(id).then(setScan);
    getVulnerabilities(id).then(setVulns);
    getLogs(id).then(setLogs);
  }, [id]);
  return (
    <div className="space-y-5">
      <Card>
        <p className="text-sm text-slate-400">Scan #{id}</p>
        <h1 className="mt-2 break-all text-2xl font-black">{scan?.target_url}</h1>
        <div className="mt-4 h-2 rounded-full bg-slate-800"><div className="h-2 rounded-full bg-cyanfire" style={{ width: `${scan?.progress || 0}%` }} /></div>
      </Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="font-bold">Findings</h2>
          <div className="mt-4 space-y-3">
            {vulns.map((vuln) => (
              <Link key={vuln.id} to={`/vulnerabilities/${vuln.id}`} className="block rounded-md border border-slate-800 bg-slate-950/40 p-3 hover:border-cyanfire/40">
                <div className="flex items-center justify-between gap-3"><span className="font-semibold">{vuln.title}</span><SeverityBadge severity={vuln.severity} /></div>
                <p className="mt-2 break-all text-xs text-slate-400">{vuln.endpoint}</p>
              </Link>
            ))}
            {!vulns.length && <p className="text-sm text-slate-400">No vulnerabilities recorded yet.</p>}
          </div>
        </Card>
        <Card>
          <h2 className="font-bold">Realtime Logs</h2>
          <div className="mt-4 max-h-96 space-y-2 overflow-auto font-mono text-xs text-slate-300">
            {logs.map((log) => <p key={log.id}><span className="text-cyanfire">{log.level}</span> {log.message}</p>)}
          </div>
        </Card>
      </div>
    </div>
  );
}

