import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "react-hot-toast";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./layouts/AppLayout";
import { AuthLayout } from "./layouts/AuthLayout";
import { Dashboard } from "./pages/Dashboard";
import { Landing } from "./pages/Landing";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { Reports } from "./pages/Reports";
import { ScanDetail } from "./pages/ScanDetail";
import { Settings } from "./pages/Settings";
import { VulnerabilityDetail } from "./pages/VulnerabilityDetail";
import "./styles.css";

const demoToken =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFuYWx5c3QiLCJleHAiOjE3NzkyNDgzNDF9.yjdzQ-FW3knlki6Cd1sZFH7q4SBU14JFotcGdGllyv8";

if (window.location.search.includes("demo=1")) {
  localStorage.setItem("sentinel_token", demoToken);
}

function Protected({ children }: { children: React.ReactNode }) {
  return localStorage.getItem("sentinel_token") ? children : <Navigate to="/login" replace />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Toaster position="top-right" toastOptions={{ style: { background: "#0d1421", color: "#e5f7ff", border: "1px solid #1f334d" } }} />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route element={<AuthLayout />}>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
        </Route>
        <Route
          element={
            <Protected>
              <AppLayout />
            </Protected>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/vulnerabilities/:id" element={<VulnerabilityDetail />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
