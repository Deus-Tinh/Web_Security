import { Outlet } from "react-router-dom";

export function AuthLayout() {
  return (
    <main className="min-h-screen bg-grid bg-[size:34px_34px] px-4 py-10 text-slate-100">
      <div className="scanline" />
      <Outlet />
    </main>
  );
}

