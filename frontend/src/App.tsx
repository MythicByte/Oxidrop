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

function AppRoutes() {
  const [user, setUser] = useState<{
    username: string;
    password_must_be_changed: boolean;
  } | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    let active = true;

    const checkAuth = async () => {
      try {
        const { response, data } = await client.GET("/api/v1/get_user");
        if (!active) return;

        if (response.ok && data) {
          setUser({
            username: data.username,
            password_must_be_changed: data.password_must_be_changed,
          });
          localStorage.setItem("username", data.username);
        }
        setAuthChecked(true);
      } catch (error) {
        console.error("Auth check failed:", error);
        if (active) setAuthChecked(true);
      }
    };

    void checkAuth();
    return () => {
      active = false;
    };
  }, []);

  if (!authChecked) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
        <p className="text-muted-foreground animate-pulse">
          Verifying secure session...
        </p>
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={user
          ? (
            <Navigate
              to={user.password_must_be_changed
                ? "/change-password"
                : "/dashboard"}
              replace
            />
          )
          : (
            <LoginForm
              onAuthenticated={(authenticatedUser) => {
                setUser(authenticatedUser);
              }}
            />
          )}
      />

      <Route
        element={
          <ProtectedRoute
            isAuthenticated={user !== null}
            passwordMustBeChanged={user?.password_must_be_changed}
          />
        }
      >
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route
          path="/change-password"
          element={
            <ChangePassword
              onLogout={() => setUser(null)}
              onPasswordChanged={() => {
                setUser((currentUser) =>
                  currentUser
                    ? { ...currentUser, password_must_be_changed: false }
                    : currentUser
                );
              }}
            />
          }
        />

        <Route
          path="/dashboard"
          element={<Dashboard onLogout={() => setUser(null)} />}
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

      <Route
        path="*"
        element={<Navigate to={user ? "/dashboard" : "/login"} replace />}
      />
    </Routes>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}

export default App;
