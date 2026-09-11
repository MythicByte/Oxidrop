import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router";
import {
  ChevronDown,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  ScrollText,
  Settings,
  ShieldCheck,
  Sun,
  User,
  Users,
  X,
} from "lucide-react";
import { Button } from "./ui/button.tsx";
import { client } from "./api.tsx";

const navigation = [
  { label: "Overview", to: "/dashboard", icon: LayoutDashboard, end: true },
  { label: "Allow lists", to: "/dashboard/allow-lists", icon: Network },
  { label: "Configuration", to: "/dashboard/configuration", icon: Settings },
];

export function Dashboard() {
  const navigate = useNavigate();
  const username = localStorage.getItem("username") || "Operator";
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [adapterState, setAdapterState] = useState<{
    available: { index: number; name: string }[];
    incoming?: { index: number; name: string } | null;
    output?: { index: number; name: string } | null;
    enforcement_active: boolean;
  }>({ available: [], enforcement_active: false });
  const [roleData, setRoleData] = useState<
    { role: string; permissions: string[] } | null
  >(null);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const storedTheme = localStorage.getItem("theme");
    const prefersDark =
      globalThis.matchMedia("(prefers-color-scheme: dark)").matches;
    const dark = storedTheme ? storedTheme === "dark" : prefersDark;
    setIsDarkMode(dark);
    document.documentElement.classList.toggle("dark", dark);
  }, []);

  useEffect(() => {
    const closeProfile = (event: MouseEvent) => {
      if (
        profileRef.current &&
        !profileRef.current.contains(event.target as Node)
      ) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", closeProfile);
    return () => document.removeEventListener("mousedown", closeProfile);
  }, []);

  useEffect(() => {
    if (roleData) return;
    void client.GET("/api/v1/role_and_permissions").then(
      ({ response, data }) => {
        if (response.ok && data) setRoleData(data);
      },
    ).catch((error: unknown) => {
      console.error("Failed to load operator profile:", error);
    });
  }, [isProfileModalOpen, roleData]);

  useEffect(() => {
    let active = true;
    const loadAdapters = () => {
      void client.GET("/api/v1/config/adapters").then(({ response, data }) => {
        if (active && response.ok && data) setAdapterState(data);
      }).catch((error: unknown) => {
        console.error("Failed to load network adapters:", error);
      });
    };
    loadAdapters();
    const interval = globalThis.setInterval(loadAdapters, 5_000);
    return () => {
      active = false;
      globalThis.clearInterval(interval);
    };
  }, []);

  const toggleTheme = () => {
    const next = !isDarkMode;
    setIsDarkMode(next);
    localStorage.setItem("theme", next ? "dark" : "light");
    document.documentElement.classList.toggle("dark", next);
  };

  const adminNavigation = roleData?.role === "Admin"
    ? [
      { label: "Users", to: "/dashboard/users", icon: Users, end: false },
      { label: "Logs", to: "/dashboard/logs", icon: ScrollText, end: false },
    ]
    : [];
  const visibleNavigation = [...navigation, ...adminNavigation];

  const handleLogout = async () => {
    try {
      await client.GET("/api/v1/logout");
    } catch (error) {
      console.error("Failed to cleanly logout from server:", error);
    } finally {
      localStorage.removeItem("username");
      globalThis.location.replace("/login");
    }
  };

  return (
    <div className="min-h-screen bg-muted/30 text-foreground">
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b bg-background/95 px-4 backdrop-blur md:px-8">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            aria-label="Open navigation"
            onClick={() => setIsMenuOpen(true)}
          >
            <Menu />
          </Button>
          <button
            type="button"
            className="flex items-center gap-2 text-left"
            onClick={() => navigate("/dashboard")}
          >
            <span className="grid size-9 place-items-center rounded-md bg-primary text-primary-foreground shadow-sm">
              <ShieldCheck className="size-5" />
            </span>
            <span>
              <span className="block text-base font-bold tracking-tight">
                OxiDrop
              </span>
              <span className="hidden text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground sm:block">
                eBPF firewall
              </span>
            </span>
          </button>
        </div>

        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            aria-label={isDarkMode
              ? "Switch to light mode"
              : "Switch to dark mode"}
            title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
            onClick={toggleTheme}
          >
            {isDarkMode ? <Sun /> : <Moon />}
          </Button>
          <div className="relative" ref={profileRef}>
            <Button
              variant="ghost"
              className="gap-2 rounded-md px-2.5"
              onClick={() => setIsProfileOpen((open) => !open)}
              aria-expanded={isProfileOpen}
            >
              <span className="grid size-8 place-items-center rounded-full bg-primary/15 text-primary">
                <User className="size-4" />
              </span>
              <span className="hidden text-sm font-medium sm:block">
                {username}
              </span>
              <ChevronDown className="size-4 text-muted-foreground" />
            </Button>
            {isProfileOpen && (
              <div className="absolute right-0 top-12 w-52 overflow-hidden rounded-xl border bg-background p-1 shadow-xl">
                <button
                  type="button"
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm hover:bg-muted"
                  onClick={() => {
                    setIsProfileModalOpen(true);
                    setIsProfileOpen(false);
                  }}
                >
                  <User className="size-4" /> Operator profile
                </button>
                <button
                  type="button"
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm text-destructive hover:bg-destructive/10"
                  onClick={handleLogout}
                >
                  <LogOut className="size-4" /> Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="flex w-full">
        <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-60 shrink-0 flex-col border-r bg-background/70 px-3 py-6 md:flex">
          <p className="px-3 pb-3 text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
            Control plane
          </p>
          <nav className="space-y-1">
            {visibleNavigation.map(({ label, to, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-primary text-primary-foreground shadow-sm"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  }`}
              >
                <Icon className="size-4" /> {label}
              </NavLink>
            ))}
          </nav>
          <div className="mt-auto rounded-md border bg-muted/40 p-4">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold">
              <span
                className={`size-2 rounded-full ${
                  adapterState.enforcement_active
                    ? "bg-emerald-500"
                    : "bg-amber-500"
                }`}
              />
              {adapterState.enforcement_active
                ? "Firewall online"
                : "Firewall offline"}
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {adapterState.enforcement_active
                ? "Policy enforcement is active on the attached interfaces."
                : "No eBPF program is connected; policy enforcement is inactive."}
            </p>
            <div className="mt-4 border-t pt-3">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Network adapters
              </p>
              {adapterState.available.length > 0
                ? (
                  <div className="mt-2 space-y-1.5">
                    {adapterState.available.map((adapter) => {
                      const attached =
                        adapter.index === adapterState.incoming?.index ||
                        adapter.index === adapterState.output?.index;
                      return (
                        <div
                          key={`${adapter.index}-${adapter.name}`}
                          className="flex items-center justify-between text-xs"
                        >
                          <span className="truncate font-medium">
                            {adapter.index} — {adapter.name}
                          </span>
                          <span
                            className={attached
                              ? "text-emerald-600"
                              : "text-muted-foreground"}
                          >
                            {attached ? "Attached" : "Ready"}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )
                : (
                  <p className="mt-2 text-xs text-muted-foreground">
                    No adapters reported
                  </p>
                )}
              <button
                type="button"
                className="mt-3 text-xs font-semibold text-primary hover:underline"
                onClick={() => navigate("/dashboard/configuration")}
              >
                Choose adapters
              </button>
            </div>
          </div>
        </aside>

        {isMenuOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/30 md:hidden"
            onClick={() => setIsMenuOpen(false)}
          >
            <aside
              className="h-full w-72 border-r bg-background p-4 shadow-xl"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="mb-6 flex items-center justify-between">
                <span className="font-semibold">Navigation</span>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setIsMenuOpen(false)}
                  aria-label="Close navigation"
                >
                  <X />
                </Button>
              </div>
              <nav className="space-y-1">
                {visibleNavigation.map(({ label, to, icon: Icon, end }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={end}
                    onClick={() => setIsMenuOpen(false)}
                    className={({ isActive }) =>
                      `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium ${
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-muted"
                      }`}
                  >
                    <Icon className="size-4" /> {label}
                  </NavLink>
                ))}
              </nav>
            </aside>
          </div>
        )}

        <main className="min-w-0 flex-1">
          <Outlet />
        </main>
      </div>

      {isProfileModalOpen && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4"
          onClick={() => setIsProfileModalOpen(false)}
        >
          <section
            className="w-full max-w-md rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="mb-6 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-widest text-primary">
                  Session identity
                </p>
                <h2 className="mt-1 text-xl font-bold">Operator profile</h2>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsProfileModalOpen(false)}
                aria-label="Close profile"
              >
                <X />
              </Button>
            </div>
            <dl className="space-y-4 text-sm">
              <div className="rounded-xl bg-muted/50 p-3">
                <dt className="text-muted-foreground">Username</dt>
                <dd className="mt-1 font-semibold">{username}</dd>
              </div>
              <div className="rounded-xl bg-muted/50 p-3">
                <dt className="text-muted-foreground">Role</dt>
                <dd className="mt-1 font-semibold">
                  {roleData?.role ?? "Loading..."}
                </dd>
              </div>
              <div className="rounded-xl bg-muted/50 p-3">
                <dt className="text-muted-foreground">Permissions</dt>
                <dd className="mt-2 flex flex-wrap gap-2">
                  {roleData?.permissions.map((permission) => (
                    <span
                      key={permission}
                      className="rounded-full bg-primary/15 px-2.5 py-1 text-xs font-semibold text-primary"
                    >
                      {permission}
                    </span>
                  )) ?? "Loading..."}
                </dd>
              </div>
            </dl>
          </section>
        </div>
      )}
    </div>
  );
}
