import { Navigate, Outlet } from "react-router";

interface ProtectedRouteProps {
  isAuthenticated: boolean;
  redirectPath?: string;
}

export function ProtectedRoute({
  isAuthenticated,
  redirectPath = "/login",
}: ProtectedRouteProps) {
  if (!isAuthenticated) {
    // Redirect unauthenticated users to the login route
    return <Navigate to={redirectPath} replace />;
  }

  // Render nested routes if authenticated
  return <Outlet />;
}
