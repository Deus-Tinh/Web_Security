import { FormEvent, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Input } from "../components/ui/Input";
import { register } from "../services/api";

export function Register() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setLoading(true);
    try {
      await register({
        email: String(form.get("email")),
        full_name: String(form.get("full_name")),
        password: String(form.get("password")),
        role: "analyst"
      });
      toast.success("Account created");
      navigate("/login");
    } catch {
      toast.error("Registration failed");
    } finally {
      setLoading(false);
    }
  }
  return (
    <div className="mx-auto flex min-h-[80vh] max-w-md items-center">
      <Card className="w-full">
        <h1 className="text-2xl font-bold">Create Analyst</h1>
        <p className="mt-2 text-sm text-slate-400">Provision a secure dashboard account.</p>
        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          <Input name="full_name" placeholder="Full name" required />
          <Input name="email" type="email" placeholder="analyst@company.com" required />
          <Input name="password" type="password" minLength={10} placeholder="Strong password" required />
          <Button className="w-full" disabled={loading}>{loading ? "Creating..." : "Register"}</Button>
        </form>
        <p className="mt-5 text-sm text-slate-400">Already registered? <Link className="text-cyanfire" to="/login">Sign in</Link></p>
      </Card>
    </div>
  );
}

