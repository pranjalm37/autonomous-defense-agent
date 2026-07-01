import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Shield, LogIn, Lock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useLogin } from "@/hooks/useAuth";

export default function Login() {
  const login = useLogin();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: string } };
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate(location.state?.from ?? "/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      {/* Hexagonal grid backdrop — a nod to network topology */}
      <svg className="pointer-events-none absolute inset-0 h-full w-full opacity-[0.06]" aria-hidden>
        <defs>
          <pattern id="hex" width="40" height="46" patternUnits="userSpaceOnUse" patternTransform="scale(1.5)">
            <path d="M20 0 L40 11.5 L40 34.5 L20 46 L0 34.5 L0 11.5 Z" fill="none" stroke="hsl(187 84% 53%)" strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#hex)" />
      </svg>

      <Card className="z-10 w-full max-w-sm">
        <CardContent className="p-7">
          <div className="mb-6 text-center">
            <Shield className="mx-auto mb-2 size-10 text-primary" />
            <h1 className="text-xl font-bold tracking-tight">AADA</h1>
            <p className="text-xs text-muted-foreground">Autonomous Defense Agent · SOC</p>
          </div>

          <form onSubmit={submit} className="space-y-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">Email</label>
              <Input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@aada.local" autoFocus />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">Password</label>
              <Input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
            </div>
            {error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{error}</div>
            )}
            <Button type="submit" className="w-full" disabled={busy}>
              <LogIn className="size-4" /> {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>

          <p className="mt-5 flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground">
            <Lock className="size-3" /> JWT · MFA-ready · RBAC enforced
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
