import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import "./App.css";
import { LoginForm } from "./components/login-form.tsx";
import { AdminRoute, ProtectedRoute } from "./router.tsx";
import { Dashboard } from "./components/dashboard.tsx";
import { useEffect, useState } from "react";
import { client } from "./components/api.tsx";
import { FirewallConfiguration } from "./components/configuration.tsx";
import { UserManagement } from "./components/usermanagement.tsx";
import { DashboardOverview } from "./components/overview.tsx";
import { AllowLists } from "./components/allow-lists.tsx";
import { Logs } from "./components/logs.tsx";
import { ChangePassword } from "./components/change-password.tsx";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const { response, data } = await client.GET("/api/v1/get_user");

        if (response.ok && data) {
          setIsAuthenticated(true);
          localStorage.setItem("username", data.username);
          if (
            data.password_must_be_changed &&
            globalThis.location.pathname !== "/change-password"
          ) {
            globalThis.location.replace("/change-password");
            return;
          }
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
            : <LoginForm onAuthenticated={() => setIsAuthenticated(true)} />}
        />

        {/* ALL DASHBOARD ROUTES ARE NOW CLEANLY NESTED UNDER PROTECTED ROUTE */}
        <Route element={<ProtectedRoute isAuthenticated={isAuthenticated} />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route
            path="/change-password"
            element={<ChangePassword onLogout={() => setIsAuthenticated(false)} />}
          />

          <Route
            path="/dashboard"
            element={<Dashboard onLogout={() => setIsAuthenticated(false)} />}
          >
            <Route index element={<DashboardOverview />} />
            <Route path="allow-lists" element={<AllowLists />} />
            <Route path="configuration" element={<FirewallConfiguration />} />
            <Route path="users" element={<UserManagement />} />
            <Route element={<AdminRoute />}>
              <Route path="logs" element={<Logs />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
