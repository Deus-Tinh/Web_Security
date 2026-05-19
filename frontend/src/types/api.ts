export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Scan {
  id: number;
  target_url: string;
  status: ScanStatus;
  progress: number;
  risk_score: number;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  scan_id: number;
  title: string;
  category: string;
  severity: Severity;
  endpoint: string;
  parameter: string | null;
  evidence: string;
  recommendation: string;
  confidence: number;
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  vulnerabilities: number;
  active_scans: number;
  recent: Scan[];
}

