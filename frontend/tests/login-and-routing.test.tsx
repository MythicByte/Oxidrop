import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { LoginForm } from "../src/components/login-form.tsx";
import { AdminRoute, ProtectedRoute } from "../src/router.tsx";

const { clientMock } = vi.hoisted(() => ({
  clientMock: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
}));

vi.mock("../src/components/api.tsx", () => ({ client: clientMock }));

describe("LoginForm", () => {
  beforeEach(() => {
    clientMock.GET.mockReset();
    clientMock.POST.mockReset();
  });

  it("submits credentials and reports rejected login without redirecting", async () => {
    clientMock.POST.mockResolvedValue({
      response: new Response(null, { status: 401 }),
    });
    render(
      <MemoryRouter>
        <LoginForm />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "wrong-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Invalid username or password",
      );
    });
    expect(clientMock.POST).toHaveBeenCalledOnce();
    expect(clientMock.POST.mock.calls[0]?.[0]).toBe("/api/v1/login");
  });

  it("reveals and hides the password without changing its value", () => {
    render(
      <MemoryRouter>
        <LoginForm />
      </MemoryRouter>,
    );
    const password = screen.getByLabelText("Password");

    expect(password).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(password).toHaveAttribute("type", "text");
    fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
    expect(password).toHaveAttribute("type", "password");
  });

  it("navigates to the dashboard after a successful login", async () => {
    clientMock.POST.mockResolvedValue({
      response: new Response(null, { status: 204 }),
    });
    clientMock.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: { username: "admin", password_must_be_changed: false },
    });
    const onAuthenticated = vi.fn();

    render(
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route
            path="/login"
            element={<LoginForm onAuthenticated={onAuthenticated} />}
          />
          <Route path="/dashboard" element={<p>Dashboard page</p>} />
        </Routes>
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    await waitFor(() => {
      expect(screen.getByText("Dashboard page")).toBeInTheDocument();
    });
    expect(onAuthenticated).toHaveBeenCalledOnce();
    expect(localStorage.getItem("username")).toBe("admin");
    expect(clientMock.GET).toHaveBeenCalledWith("/api/v1/get_user");
  });

  it("reports a network error and re-enables the form", async () => {
    clientMock.POST.mockRejectedValue(new TypeError("Failed to fetch"));
    render(
      <MemoryRouter>
        <LoginForm />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Unable to reach the authentication service. Please try again.",
      );
    });
    expect(screen.getByRole("button", { name: "Sign In" })).toBeEnabled();
  });

  it("does not redirect when the new session cannot be verified", async () => {
    clientMock.POST.mockResolvedValue({
      response: new Response(null, { status: 200 }),
    });
    clientMock.GET.mockResolvedValue({
      response: new Response(null, { status: 401 }),
    });
    render(
      <MemoryRouter>
        <LoginForm />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Login succeeded, but the secure session could not be verified.",
      );
    });
  });
});

describe("route guards", () => {
  beforeEach(() => {
    clientMock.GET.mockReset();
  });

  it("redirects unauthenticated users to the login route", () => {
    render(
      <MemoryRouter initialEntries={["/private"]}>
        <Routes>
          <Route element={<ProtectedRoute isAuthenticated={false} />}>
            <Route path="/private" element={<p>Private content</p>} />
          </Route>
          <Route path="/login" element={<p>Login page</p>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Login page")).toBeInTheDocument();
    expect(screen.queryByText("Private content")).not.toBeInTheDocument();
  });

  it("redirects users with a forced password change before protected content", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route
            element={
              <ProtectedRoute
                isAuthenticated
                passwordMustBeChanged
              />
            }
          >
            <Route path="/dashboard" element={<p>Dashboard content</p>} />
            <Route
              path="/change-password"
              element={<p>Change password content</p>}
            />
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Change password content")).toBeInTheDocument();
    expect(screen.queryByText("Dashboard content")).not.toBeInTheDocument();
  });

  it("redirects a non-admin away from the admin route", async () => {
    clientMock.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: { role: "Viewer", permissions: [] },
    });
    render(
      <MemoryRouter initialEntries={["/admin"]}>
        <Routes>
          <Route element={<AdminRoute />}>
            <Route path="/admin" element={<p>Admin content</p>} />
          </Route>
          <Route path="/dashboard" element={<p>Dashboard content</p>} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("Dashboard content")).toBeInTheDocument();
    });
    expect(screen.queryByText("Admin content")).not.toBeInTheDocument();
    expect(clientMock.GET).toHaveBeenCalledWith(
      "/api/v1/role_and_permissions",
    );
  });
});
