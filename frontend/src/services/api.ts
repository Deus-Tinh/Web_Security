import axios from "axios";
import type { DashboardStats, Scan, Vulnerability } from "../types/api";

const baseURL = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

export const api = axios.create({ baseURL });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("sentinel_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export async function login(email: string, password: string) {
  const { data } = await api.post("/auth/login", { email, password });
  localStorage.setItem("sentinel_token", data.access_token);
  return data;
}

export async function register(payload: { email: string; full_name: string; password: string; role: string }) {
  return api.post("/auth/register", payload);
}

export async function getStats() {
  const { data } = await api.get<DashboardStats>("/dashboard/stats");
  return data;
}

export async function createScan(target_url: string, max_depth = 2) {
  const { data } = await api.post<Scan>("/scans", { target_url, max_depth, respect_robots: true });
  return data;
}

export async function listScans() {
  const { data } = await api.get<Scan[]>("/scans");
  return data;
}

export async function getScan(id: string) {
  const { data } = await api.get<Scan>(`/scans/${id}`);
  return data;
}

export async function getVulnerabilities(scanId: string) {
  const { data } = await api.get<Vulnerability[]>(`/scans/${scanId}/vulnerabilities`);
  return data;
}

export async function getVulnerability(id: string) {
  const { data } = await api.get<Vulnerability>(`/scans/vulnerabilities/${id}`);
  return data;
}

export async function getLogs(scanId: string) {
  const { data } = await api.get(`/scans/${scanId}/logs`);
  return data;
}

export interface ReportItem {
  id: number;
  scan_id: number;
  target_url: string;
  format: "pdf" | "json";
  file_path: string;
  created_at: string;
}

export async function listReports() {
  const { data } = await api.get<ReportItem[]>("/reports");
  return data;
}

export function reportDownloadUrl(reportId: number) {
  return `${baseURL}/reports/${reportId}/download`;
}
