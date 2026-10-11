import { NavLink, Navigate, Outlet, useLocation } from "react-router";
import { pathForStage, useAuth } from "../auth";
import { roleLabel } from "../format";
import type { Role } from "../types";

const LINKS: Record<Role, { to: string; label: string }[]> = {
  REQUESTER: [
    { to: "/tickets", label: "My tickets" },
    { to: "/tickets/new", label: "New ticket" },
  ],
  AGENT: [{ to: "/queue", label: "Queue" }],
  ADMIN: [
    { to: "/admin/users", label: "Users" },
    { to: "/admin/categories", label: "Categories" },
    { to: "/admin/retention", label: "Retention" },
    { to: "/admin/audit", label: "Audit log" },
  ],
};

/** The signed-in frame. Anything else than a complete sign-in is sent to its stage. */
export function Layout() {
  const { session, logout } = useAuth();
  const location = useLocation();
  if (!session) {
    return <div className="loading">Loading…</div>;
  }
  if (session.stage !== "AUTHENTICATED" || !session.user) {
    return <Navigate to={pathForStage(session.stage)} replace state={{ from: location.pathname }} />;
  }
  const user = session.user;
  return (
    <div className="app">
      <header className="topbar">
        <NavLink to="/" className="brand">SecureDesk</NavLink>
        <nav aria-label="Main">
          {LINKS[user.role].map((link) => (
            <NavLink key={link.to} to={link.to} end>{link.label}</NavLink>
          ))}
        </nav>
        <div className="who">
          <NavLink to="/account" className="account">
            {user.displayName} <span className={`role role-${user.role.toLowerCase()}`}>{roleLabel(user.role)}</span>
          </NavLink>
          <button type="button" className="link" onClick={() => logout()}>Sign out</button>
        </div>
      </header>
      {user.mfaMandatory && !user.mfaEnabled && (
        <p className="banner warning">A second factor is required for your account.</p>
      )}
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

/** A route only one role may see. The API checks the same thing; this only keeps the menus honest. */
export function RequireRole({ role, children }: { role: Role; children: React.ReactNode }) {
  const { session } = useAuth();
  if (session?.user?.role !== role) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

export function Home() {
  const { session } = useAuth();
  switch (session?.user?.role) {
    case "REQUESTER":
      return <Navigate to="/tickets" replace />;
    case "AGENT":
      return <Navigate to="/queue" replace />;
    case "ADMIN":
      return <Navigate to="/admin/users" replace />;
    default:
      return <Navigate to="/login" replace />;
  }
}
