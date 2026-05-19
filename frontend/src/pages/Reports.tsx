import { useEffect, useMemo, useState } from "react";
import { Download, Eye, FileJson, FileText } from "lucide-react";
import toast from "react-hot-toast";
import { Card } from "../components/ui/Card";
import { listReports, reportDownloadUrl, type ReportItem } from "../services/api";

export function Reports() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [preview, setPreview] = useState<string | null>(null);

  useEffect(() => {
    listReports()
      .then(setReports)
      .catch(() => toast.error("Could not load reports"))
      .finally(() => setLoading(false));
  }, []);

  const grouped = useMemo(() => {
    return reports.reduce<Record<number, ReportItem[]>>((acc, report) => {
      acc[report.scan_id] = [...(acc[report.scan_id] || []), report];
      return acc;
    }, {});
  }, [reports]);

  async function fetchReportBlob(report: ReportItem) {
    const token = localStorage.getItem("sentinel_token");
    const url = reportDownloadUrl(report.id);
    if (!token) {
      toast.error("Please sign in again");
      throw new Error("Missing token");
    }
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) throw new Error("Report file is not ready");
    return response.blob();
  }

  async function download(report: ReportItem) {
    try {
      const blob = await fetchReportBlob(report);
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `sentinel-scan-${report.scan_id}.${report.format}`;
      link.click();
      URL.revokeObjectURL(objectUrl);
    } catch {
      toast.error("Report file is not ready");
    }
  }

  async function view(report: ReportItem) {
    try {
      const blob = await fetchReportBlob(report);
      if (report.format === "json") {
        setPreview(JSON.stringify(JSON.parse(await blob.text()), null, 2));
        return;
      }
      const objectUrl = URL.createObjectURL(blob);
      window.open(objectUrl, "_blank", "noopener,noreferrer");
    } catch {
      toast.error("Could not open report");
    }
  }

  return (
    <div className="space-y-5">
      <h1 className="text-3xl font-black">Reports</h1>
      {loading && <div className="h-40 animate-pulse rounded-lg bg-slate-900" />}
      {!loading && reports.length === 0 && (
        <Card>
          <h2 className="text-xl font-bold">No reports yet</h2>
          <p className="mt-2 text-sm text-slate-400">Run a scan first. PDF and JSON reports are generated after a scan completes.</p>
        </Card>
      )}
      {!loading && Object.entries(grouped).map(([scanId, items]) => (
        <Card key={scanId}>
          <p className="text-sm text-slate-400">Scan #{scanId}</p>
          <h2 className="mt-2 break-all text-xl font-bold">{items[0]?.target_url}</h2>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {items.map((report) => {
              const Icon = report.format === "pdf" ? FileText : FileJson;
              const title = report.format === "pdf" ? "Executive PDF" : "Machine JSON";
              return (
                <button
                  key={report.id}
                  className="rounded-md border border-slate-800 bg-slate-950/50 p-4 text-left transition hover:border-cyanfire/50 hover:bg-cyanfire/10"
                >
                  <div className="flex items-center justify-between">
                    <Icon className="text-cyanfire" />
                    <div className="flex gap-2">
                      <span
                        role="button"
                        tabIndex={0}
                        onClick={() => view(report)}
                        onKeyDown={(event) => event.key === "Enter" && view(report)}
                        className="rounded-md border border-slate-700 p-2 text-slate-300 hover:border-cyanfire hover:text-cyanfire"
                        title="View report"
                      >
                        <Eye size={16} />
                      </span>
                      <span
                        role="button"
                        tabIndex={0}
                        onClick={() => download(report)}
                        onKeyDown={(event) => event.key === "Enter" && download(report)}
                        className="rounded-md border border-slate-700 p-2 text-slate-300 hover:border-cyanfire hover:text-cyanfire"
                        title="Download report"
                      >
                        <Download size={16} />
                      </span>
                    </div>
                  </div>
                  <h3 className="mt-4 font-bold">{title}</h3>
                  <p className="mt-2 text-sm text-slate-400">View or download generated {report.format.toUpperCase()} report.</p>
                </button>
              );
            })}
          </div>
        </Card>
      ))}
      {preview && (
        <div className="fixed inset-0 z-50 bg-black/70 p-6 backdrop-blur">
          <div className="mx-auto flex h-full max-w-5xl flex-col rounded-lg border border-slate-700 bg-carbon">
            <div className="flex items-center justify-between border-b border-slate-800 p-4">
              <h2 className="font-bold">JSON Report Preview</h2>
              <button className="rounded-md border border-slate-700 px-3 py-1 text-sm" onClick={() => setPreview(null)}>Close</button>
            </div>
            <pre className="flex-1 overflow-auto p-4 text-xs leading-5 text-cyan-100">{preview}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
