import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Navigate, useNavigate } from "react-router";
import { api, ApiError } from "../api";
import { pathForStage, useAuth } from "../auth";
import { CodeList, downloadText, ErrorMessage } from "../components/Bits";
import type { Stage } from "../types";

function Frame({ title, step, children }: { title: string; step?: string; children: ReactNode }) {
  const { notice } = useAuth();
  return (
    <div className="signin">
      <div className="signin-box">
        <p className="brand-large">SecureDesk</p>
        <h1>{title}</h1>
        {step && <p className="step">{step}</p>}
        {notice && <p className="banner info" role="status">{notice}</p>}
        {children}
      </div>
    </div>
  );
}

/** Keeps a sign-in page in step with the server: a page for another stage sends you to the right one. */
function useStage(expected: Stage): Stage | null {
  const { session } = useAuth();
  if (!session) return null;
  return session.stage === expected ? null : session.stage;
}

function useAdvance() {
  const { refresh, setNotice } = useAuth();
  const navigate = useNavigate();
  return async () => {
    setNotice(null);
    const state = await refresh();
    navigate(pathForStage(state.stage), { replace: true });
  };
}

// ---- step 1: password ---------------------------------------------------------------------------

export function LoginPage() {
  const { session } = useAuth();
  const advance = useAdvance();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (session?.stage === "AUTHENTICATED") {
    return <Navigate to="/" replace />;
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.auth("/api/auth/login", { username, password });
      setPassword("");
      await advance();
    } catch (e) {
      setError(e);
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Frame title="Sign in" step="Step 1 of 2. A correct password alone does not sign you in.">
      <form onSubmit={submit} className="stack">
        <ErrorMessage error={error} />
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete="current-password" required maxLength={1024} />
        </label>
        <button type="submit" disabled={busy}>Continue</button>
      </form>
    </Frame>
  );
}

// ---- step 2: the code ---------------------------------------------------------------------------

export function CodePage() {
  const { session, logout } = useAuth();
  const advance = useAdvance();
  const wrongStage = useStage("MFA");
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (wrongStage) return <Navigate to={pathForStage(wrongStage)} replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.auth("/api/auth/mfa", { code: code.trim() });
      await advance();
    } catch (e) {
      setError(e);
      setCode("");
      if (e instanceof ApiError && e.status === 401) {
        await advance();          // locked or expired: the server ended the sign-in
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Frame title="Enter your code" step={`Step 2 of 2 for ${session?.pendingUsername ?? "your account"}. Until this succeeds, your session carries no authorities.`}>
      <form onSubmit={submit} className="stack">
        <ErrorMessage error={error} />
        <label>
          Six-digit code from your authenticator app, or a recovery code
          <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code"
                 inputMode="text" maxLength={32} required autoFocus />
        </label>
        <button type="submit" disabled={busy}>Verify</button>
        <button type="button" className="link" onClick={() => logout()}>Cancel and start again</button>
      </form>
    </Frame>
  );
}

// ---- temporary password -------------------------------------------------------------------------

export function NewPasswordPage() {
  const advance = useAdvance();
  const wrongStage = useStage("PASSWORD_CHANGE");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (wrongStage) return <Navigate to={pathForStage(wrongStage)} replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== confirm) {
      setError(new ApiError(400, "mismatch", "The two passwords are not the same."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.auth("/api/auth/password", { newPassword: password });
      await advance();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Frame title="Choose your password" step="Your administrator gave you a temporary password. Replace it now.">
      <form onSubmit={submit} className="stack">
        <ErrorMessage error={error} />
        <p className="hint">
          At least 15 characters. Spaces and any characters are welcome: a sentence you remember works well.
          Common passwords and passwords containing your name are refused. There are no other rules.
        </p>
        <label>
          New password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete="new-password" minLength={15} maxLength={128} required autoFocus />
        </label>
        <label>
          Repeat it
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
                 autoComplete="new-password" minLength={15} maxLength={128} required />
        </label>
        <button type="submit" disabled={busy}>Save password</button>
      </form>
    </Frame>
  );
}

// ---- enrolment ----------------------------------------------------------------------------------

interface Enrolment {
  secret: string;
  otpauthUri: string;
  issuer: string;
  account: string;
}

export function EnrolPage() {
  const wrongStage = useStage("ENROL");
  const advance = useAdvance();
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!wrongStage && !codes) {
      api.get<Enrolment>("/api/auth/enrol").then(setEnrolment).catch(setError);
    }
  }, [wrongStage, codes]);

  if (codes) {
    return (
      <Frame title="Your recovery codes" step="Shown once. Each works one time, if you lose your phone.">
        <div className="stack">
          <CodeList codes={codes} />
          <button type="button" className="secondary"
                  onClick={() => downloadText("securedesk-recovery-codes.txt", codes.join("\n") + "\n")}>
            Download as a text file
          </button>
          <label className="check">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            I have stored these codes somewhere safe
          </label>
          <button type="button" disabled={!saved} onClick={() => advance()}>Continue</button>
        </div>
      </Frame>
    );
  }
  if (wrongStage) return <Navigate to={pathForStage(wrongStage)} replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.auth<{ stage: Stage; recoveryCodes: string[] }>("/api/auth/enrol", { code: code.trim() });
      setCodes(result.recoveryCodes);
    } catch (e) {
      setError(e);
      setCode("");
      if (e instanceof ApiError && e.status === 401) await advance();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Frame title="Set up your second factor" step="Your account needs a code from an authenticator app at every sign-in.">
      <ErrorMessage error={error} />
      {enrolment && (
        <form onSubmit={submit} className="stack">
          <ol className="steps">
            <li>Open an authenticator app (Aegis, Google Authenticator, Microsoft Authenticator…).</li>
            <li>Scan this code, or type the key below.</li>
          </ol>
          <img className="qr" src="/api/auth/enrol/qr.svg" alt="QR code with the authenticator key" width={240} height={240} />
          <p className="secret">
            <span>Key</span> <code>{enrolment.secret.match(/.{1,4}/g)?.join(" ")}</code>
          </p>
          <label>
            3. Enter the six-digit code the app now shows
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric"
                   autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required />
          </label>
          <button type="submit" disabled={busy}>Turn on the second factor</button>
        </form>
      )}
    </Frame>
  );
}
