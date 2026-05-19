import { Shield, ToggleRight } from "lucide-react";
import { Card } from "../components/ui/Card";

export function Settings() {
  return (
    <div className="space-y-5">
      <h1 className="text-3xl font-black">Settings</h1>
      <Card>
        <div className="flex items-center gap-3"><Shield className="text-cyanfire" /><h2 className="font-bold">Security Scope</h2></div>
        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="rounded-md border border-slate-800 bg-slate-950/50 p-4">
            <p className="text-sm text-slate-400">Allowed hosts</p>
            <p className="mt-2 font-mono text-cyan-100">localhost, 127.0.0.1</p>
          </div>
          <div className="rounded-md border border-slate-800 bg-slate-950/50 p-4">
            <p className="text-sm text-slate-400">Rate limiting</p>
            <p className="mt-2 flex items-center gap-2 font-mono text-cyan-100"><ToggleRight /> 120 requests/min</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
