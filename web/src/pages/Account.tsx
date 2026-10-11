import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Card, CodeList, downloadText, ErrorMessage } from "../components/Bits";
import { roleLabel } from "../format";

export function AccountPage() {
  const { session, refresh } = useAuth();
  const user = session?.user;
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<string[] | null>(null);

  if (!user) return null;

  const changePassword = async (event: FormEvent) => {
    event.preventDefault();
    setMessage(null);
    setError(null);
    if (next !== confirm) {
      setError(new ApiError(400, "mismatch", "The two new passwords are not the same."));
      return;
    }
    try {
      await api.post("/api/account/password", { currentPassword: current, newPassword: next });
      setCurrent("");
      setNext("");
      setConfirm("");
      setMessage("Password changed. Your other sessions have been signed out.");
      await refresh();
    } catch (e) {
      setError(e);
    }
  };

  const newCodes = async () => {
    setError(null);
    try {
      const result = await api.post<{ recoveryCodes: string[] }>("/api/account/recovery-codes");
      setCodes(result.recoveryCodes);
      await refresh();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="stack-cards">
      <Card title="Your account">
        <dl className="facts">
          <dt>Name</dt><dd>{user.displayName}</dd>
          <dt>Username</dt><dd>{user.username}</dd>
          <dt>Role</dt><dd>{roleLabel(user.role)}</dd>
          <dt>Second factor</dt><dd>{user.mfaEnabled ? "Authenticator app" : "None"}</dd>
          {user.mfaEnabled && (<><dt>Recovery codes left</dt><dd>{user.recoveryCodesLeft}</dd></>)}
        </dl>
        {user.mfaEnabled && !codes && (
          <button type="button" className="secondary" onClick={newCodes}>Replace my recovery codes</button>
        )}
        {codes && (
          <div className="banner secret-box">
            <p>Your new recovery codes. The old ones no longer work. Shown once.</p>
            <CodeList codes={codes} />
            <button type="button" className="secondary"
                    onClick={() => downloadText("securedesk-recovery-codes.txt", codes.join("\n") + "\n")}>Download</button>
            <button type="button" className="link" onClick={() => setCodes(null)}>Done</button>
          </div>
        )}
      </Card>
      <Card title="Change password">
        <form onSubmit={changePassword} className="stack">
          <ErrorMessage error={error} />
          {message && <p className="ok" role="status">{message}</p>}
          <label>Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
          </label>
          <label>New password (at least 15 characters)
            <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password"
                   minLength={15} maxLength={128} required />
          </label>
          <label>Repeat the new password
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password"
                   minLength={15} maxLength={128} required />
          </label>
          <button type="submit">Change password</button>
        </form>
      </Card>
    </div>
  );
}
