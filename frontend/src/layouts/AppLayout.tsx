import { Activity, FileText, Gauge, LogOut, Settings, Shield } from "lucide-react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

const nav = [
  { to: "/dashboard", label: "Dashboard", icon: Gauge },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings }
];

export function AppLayout() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen text-slate-100">
      <div className="scanline" />
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-slate-800 bg-carbon/90 p-5 lg:block">
        <div className="flex items-center gap-3">
          <div className="rounded-md border border-cyanfire/40 bg-cyanfire/10 p-2 text-cyanfire"><Shield size={22} /></div>
          <div>
            <p className="font-bold tracking-wide">SentinelAI</p>
            <p className="text-xs text-slate-400">Security Operations</p>
          </div>
        </div>
        <nav className="mt-10 space-y-2">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-3 text-sm transition ${isActive ? "bg-cyanfire/15 text-cyan-100" : "text-slate-400 hover:bg-slate-900 hover:text-slate-100"}`
              }
            >
              <item.icon size={18} /> {item.label}
            </NavLink>
          ))}
        </nav>
        <button
          className="absolute bottom-5 flex items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-400 hover:text-slate-100"
          onClick={() => {
            localStorage.removeItem("sentinel_token");
            navigate("/login");
          }}
        >
          <LogOut size={18} /> Sign out
        </button>
      </aside>
      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-800 bg-carbon/70 px-5 py-4 backdrop-blur">
          <div className="flex items-center gap-2 text-sm text-slate-400"><Activity size={16} className="text-acid" /> Live monitoring enabled</div>
          <span className="rounded-md border border-acid/30 bg-acid/10 px-2 py-1 text-xs font-semibold text-acid">Authorized Targets Only</span>
        </header>
        <div className="p-5 lg:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

