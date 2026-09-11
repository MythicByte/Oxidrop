import { useState } from "react";
import type { SubmitEvent } from "react";
import { useNavigate } from "react-router";
import { Eye, EyeOff, KeyRound, LogOut } from "lucide-react";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";

interface ChangePasswordProps {
  onLogout?: () => void;
}

export function ChangePassword({ onLogout }: ChangePasswordProps) {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [visible, setVisible] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const passwordLengthValid = password.length >= 12 && password.length <= 120;
  const confirmationMatches = confirmation.length > 0 &&
    password === confirmation;

  async function logout() {
    try {
      const response = await fetch("/api/v1/logout", {
        credentials: "include",
      });
      if (!response.ok && response.status !== 303) {
        console.error(`Logout failed with HTTP ${response.status}`);
      }
    } catch (reason) {
      console.error("Logout request failed:", reason);
    } finally {
      onLogout?.();
      navigate("/login", { replace: true });
    }
  }

  async function submit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password.length < 12 || password.length > 120) {
      setError("Password must be between 12 and 120 characters.");
      return;
    }
    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const response = await fetch("/api/v1/change_password", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (!response.ok) {
        const message = await response.text();
        if (response.status === 409) {
          onLogout?.();
          navigate("/login", { replace: true });
          return;
        }
        setError(
          message || `Unable to change password (HTTP ${response.status}).`,
        );
        return;
      }
      navigate("/dashboard", { replace: true });
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to change password.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-5" /> Change your password
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            A new password is required before continuing.
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-4">
            <div className="relative">
              <input
                aria-label="New password"
                autoFocus
                required
                minLength={12}
                maxLength={120}
                type={visible ? "text" : "password"}
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  setError(null);
                }}
                className="h-10 w-full rounded-lg border border-input bg-background px-3 pr-10 text-sm"
                placeholder="New password (12–120 characters)"
              />
            </div>
            <div
              className={`h-1 rounded-full transition-colors ${
                passwordLengthValid ? "bg-emerald-500" : "bg-muted"
              }`}
              aria-label={passwordLengthValid
                ? "Password length is valid"
                : "Password must be 12 to 120 characters"}
            />
            <div className="relative">
              <input
                aria-label="Confirm new password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={120}
                type={visible ? "text" : "password"}
                value={confirmation}
                onChange={(event) => {
                  setConfirmation(event.target.value);
                  setError(null);
                }}
                className="h-10 w-full rounded-lg border border-input bg-background px-3 pr-10 text-sm"
                placeholder="Confirm new password"
              />
              <button
                type="button"
                onClick={() => setVisible((value) => !value)}
                className="absolute inset-y-0 right-0 grid w-10 place-items-center text-muted-foreground"
                aria-label={visible ? "Hide passwords" : "Show passwords"}
              >
                {visible
                  ? <EyeOff className="size-4" />
                  : <Eye className="size-4" />}
              </button>
            </div>
            <div
              className={`h-1 rounded-full transition-colors ${
                confirmationMatches ? "bg-emerald-500" : "bg-muted"
              }`}
              aria-label={confirmationMatches
                ? "Passwords match"
                : "Passwords must match"}
            />
            <p
              className={`text-xs ${
                passwordLengthValid
                  ? "text-emerald-600"
                  : "text-muted-foreground"
              }`}
            >
              {password.length}/120 characters; minimum 12
            </p>
            {error && (
              <p role="alert" className="text-sm text-destructive">{error}</p>
            )}
            <div className="flex gap-2">
              <Button type="submit" className="flex-1" disabled={saving}>
                {saving ? "Saving…" : "Set password"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={logout}
                disabled={saving}
                aria-label="Log out"
              >
                <LogOut className="size-4" /> Log out
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
