import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import "./App.css";
import { LoginForm } from "@/components/login-form";
import { ProtectedRoute } from "./router";
import { Dashboard } from "./components/dashboard";
import { useEffect, useState } from "react";
import { client } from "./components/api";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Ask the Rust backend if our HttpOnly cookie is still valid
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
        <p className="text-muted-foreground animate-pulse">Verifying secure session...</p>
      </div>
    );
  }

return (
    <BrowserRouter>
      <Routes>
        {/* If already authenticated, redirect away from login page */}
        <Route 
          path="/login" 
          element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <LoginForm />} 
        />

        <Route element={<ProtectedRoute isAuthenticated={isAuthenticated} />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
export default App;
