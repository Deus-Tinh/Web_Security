import { FormEvent, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Input } from "../components/ui/Input";
import { login } from "../services/api";

export function Login() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setLoading(true);
    try {
      await login(String(form.get("email")), String(form.get("password")));
      toast.success("Welcome back");
      navigate("/dashboard");
    } catch {
      toast.error("Invalid credentials");
    } finally {
      setLoading(false);
    }
  }
  return (
    <div className="mx-auto flex min-h-[80vh] max-w-md items-center">
      <Card className="w-full">
        <h1 className="text-2xl font-bold">Operator Login</h1>
        <p className="mt-2 text-sm text-slate-400">Access the authorized scanning console.</p>
        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          <Input name="email" type="email" placeholder="analyst@company.com" required />
          <Input name="password" type="password" placeholder="Password" required />
          <Button className="w-full" disabled={loading}>{loading ? "Authenticating..." : "Sign in"}</Button>
        </form>
        <p className="mt-5 text-sm text-slate-400">New analyst? <Link className="text-cyanfire" to="/register">Create account</Link></p>
      </Card>
    </div>
  );
}

