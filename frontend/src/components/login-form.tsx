import { useState } from "react";
import type { SubmitEvent } from "react";
import { useNavigate } from "react-router";
import { Eye, EyeOff } from "lucide-react";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";
import { Input } from "./ui/input.tsx";
import { Label } from "./ui/label.tsx";
import { client } from "./api.tsx";

interface LoginFormProps {
  onAuthenticated?: () => void;
}

export function LoginForm({ onAuthenticated }: LoginFormProps) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    const formData = new FormData(e.currentTarget);
    const username = formData.get("username") as string;
    const password = formData.get("password") as string;

    const { response } = await client.POST("/api/v1/login", {
      body: { username, password },
      bodySerializer(body) {
        return new URLSearchParams(body as Record<string, string>).toString();
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    setIsLoading(false);

    if (!response.ok) {
      if (response.status === 401) {
        setError("Invalid username or password");
      } else {
        setError(`Authentication failed: server returned ${response.status}`);
      }
      return;
    }

    const userResponse = await fetch("/api/v1/get_user", {
      credentials: "include",
    });
    const user = userResponse.ok
      ? await userResponse.json() as {
        username?: string;
        password_must_be_changed?: boolean;
      }
      : null;
    if (user?.username) {
      localStorage.setItem("username", user.username);
    }
    onAuthenticated?.();
    navigate(
      user?.password_must_be_changed ? "/change-password" : "/dashboard",
      { replace: true },
    );
  };

  return (
    // add Icon later
    <div className="flex min-h-screen flex-col items-center justify-center p-4 bg-background">
      <h1 className="text-4xl font-bold mb-8 tracking-tight">OxiDrop</h1>

      <Card className="w-full max-w-sm shadow-lg">
        <CardHeader>
          <CardTitle className="text-3xl text-center">Login</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                name="username"
                type="text"
                placeholder="user"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="password"
                  required
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 grid w-10 place-items-center text-muted-foreground hover:text-foreground"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword
                    ? <EyeOff className="size-4" />
                    : <Eye className="size-4" />}
                </button>
              </div>
            </div>
            {error && (
              <p role="alert" className="text-sm font-medium text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Signing In..." : "Sign In"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
