import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import "./App.css";
import { LoginForm } from "@/components/login-form";
import { ProtectedRoute } from "./router";
import { Dashboard } from "./components/dashboard";
import { useEffect, useState } from "react";
import { client } from "./components/api";
import { FirewallConfiguration } from "./components/configuration";
import { UserManagement } from "./components/usermanagement";
import { DashboardOverview } from "./components/overview";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const { response, data } = await client.GET("/api/v1/get_user");

        if (response.ok && data) {
          setIsAuthenticated(true);
          localStorage.setItem("username", data.username);
        } else {
          setIsAuthenticated(false);
        }
      } catch (error) {
        console.error("Auth check failed:", error);
        setIsAuthenticated(false);
      }
    };

    checkAuth();
  }, []);

  if (isAuthenticated === null) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
        <p className="text-muted-foreground animate-pulse">
          Verifying secure session...
        </p>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        {/* If already authenticated, redirect away from login page */}
        <Route
          path="/login"
          element={isAuthenticated
            ? <Navigate to="/dashboard" replace />
            : <LoginForm />}
        />

        {/* ALL DASHBOARD ROUTES ARE NOW CLEANLY NESTED UNDER PROTECTED ROUTE */}
        <Route element={<ProtectedRoute isAuthenticated={isAuthenticated} />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          <Route path="/dashboard" element={<Dashboard />}>
            <Route index element={<DashboardOverview />} />
            <Route path="configuration" element={<FirewallConfiguration />} />
            <Route path="users" element={<UserManagement />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
