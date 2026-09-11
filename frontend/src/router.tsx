import { Navigate, Outlet, useLocation } from "react-router";
import { useEffect, useState } from "react";
import { client } from "./components/api.tsx";

interface ProtectedRouteProps {
  isAuthenticated: boolean;
  passwordMustBeChanged?: boolean;
  redirectPath?: string;
}

export function ProtectedRoute({
  isAuthenticated,
  passwordMustBeChanged = false,
  redirectPath = "/login",
}: ProtectedRouteProps) {
  const location = useLocation();

  if (!isAuthenticated) {
    // Redirect unauthenticated users to the login route
    return <Navigate to={redirectPath} replace />;
  }

  if (passwordMustBeChanged && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }

  // Render nested routes if authenticated
  return <Outlet />;
}

export function AdminRoute() {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);

  useEffect(() => {
    let active = true;
    void client.GET("/api/v1/role_and_permissions").then(
      ({ response, data }) => {
        if (active) setIsAdmin(response.ok && data?.role === "Admin");
      },
    ).catch((error: unknown) => {
      console.error("Failed to verify administrator access:", error);
      if (active) setIsAdmin(false);
    });
    return () => {
      active = false;
    };
  }, []);

  if (isAdmin === null) {
    return (
      <div className="flex min-h-96 items-center justify-center text-sm text-muted-foreground">
        Verifying administrator access…
      </div>
    );
  }

  return isAdmin ? <Outlet /> : <Navigate to="/dashboard" replace />;
}
