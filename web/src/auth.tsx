import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getSession, onSessionEnded, api } from "./api";
import type { SessionState, Stage } from "./types";

interface AuthContextValue {
  session: SessionState | null;
  /** Asks the API where the session stands; called after every sign-in step. */
  refresh: () => Promise<SessionState>;
  logout: () => Promise<void>;
  notice: string | null;
  setNotice: (notice: string | null) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const state = await getSession();
    setSession(state);
    return state;
  }, []);

  const logout = useCallback(async () => {
    await api.post("/api/auth/logout").catch(() => undefined);
    await refresh();
  }, [refresh]);

  useEffect(() => {
    refresh().catch(() => setSession({ stage: "ANONYMOUS", user: null, pendingUsername: null, csrfToken: null }));
    onSessionEnded(() => {
      setNotice("Your session has ended. Please sign in again.");
      refresh().catch(() => undefined);
    });
    return () => onSessionEnded(null);
  }, [refresh]);

  const value = useMemo(() => ({ session, refresh, logout, notice, setNotice }), [session, refresh, logout, notice]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth outside AuthProvider");
  }
  return context;
}

/** Where each stage of the sign-in lives. */
export function pathForStage(stage: Stage): string {
  switch (stage) {
    case "MFA":
      return "/login/code";
    case "ENROL":
      return "/login/enrol";
    case "PASSWORD_CHANGE":
      return "/login/new-password";
    case "AUTHENTICATED":
      return "/";
    default:
      return "/login";
  }
}
