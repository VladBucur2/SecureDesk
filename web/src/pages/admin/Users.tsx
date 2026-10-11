import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, query } from "../../api";
import { useAuth } from "../../auth";
import { Card, ErrorMessage, Pager } from "../../components/Bits";
import { formatDate, roleLabel } from "../../format";
import type { Page, Role, TemporaryPasswordView, UserView } from "../../types";

const ROLES: Role[] = ["REQUESTER", "AGENT", "ADMIN"];

/** UC-05. Every change asks for a fresh code first if the last sign-in is older than ten minutes. */
export function UsersPage() {
  const { session } = useAuth();
  const [page, setPage] = useState(0);
  const [data, setData] = useState<Page<UserView> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [secret, setSecret] = useState<{ username: string; password: string } | null>(null);

  const load = useCallback(() => {
    api.get<Page<UserView>>(`/api/admin/users${query({ page, size: 25 })}`).then(setData).catch(setError);
  }, [page]);
  useEffect(load, [load]);

  const act = async (action: () => Promise<unknown>) => {
    setError(null);
    try {
      await action();
      load();
    } catch (e) {
      setError(e);
    }
  };

  const showTemporary = (result: TemporaryPasswordView) =>
    setSecret({ username: result.user.username, password: result.temporaryPassword });

  return (
    <div className="stack-cards">
      <CreateUser onCreated={(result) => { showTemporary(result); load(); }} />
      {secret && (
        <div className="banner secret-box" role="status">
          <p>Temporary password for <strong>{secret.username}</strong>. It is shown once; hand it over in person or by phone.
            The user must replace it and set up a second factor at the first sign-in.</p>
          <code>{secret.password}</code>
          <button type="button" className="secondary" onClick={() => setSecret(null)}>I have handed it over</button>
        </div>
      )}
      <Card title="Accounts">
        <ErrorMessage error={error} />
        {data && (
          <>
            <table className="users">
              <thead>
                <tr><th>User</th><th>Role</th><th>Status</th><th>Second factor</th><th>Created</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {data.items.map((user) => (
                  <UserRow key={user.id} user={user} self={user.id === session?.user?.id} act={act} onTemporary={showTemporary} />
                ))}
              </tbody>
            </table>
            <Pager page={data.page} size={data.size} total={data.total} onPage={setPage} />
          </>
        )}
      </Card>
    </div>
  );
}

function UserRow({ user, self, act, onTemporary }: {
  user: UserView;
  self: boolean;
  act: (action: () => Promise<unknown>) => void;
  onTemporary: (result: TemporaryPasswordView) => void;
}) {
  const [confirmErase, setConfirmErase] = useState("");
  const [erasing, setErasing] = useState(false);
  const path = `/api/admin/users/${user.id}`;

  if (user.erased) {
    return (
      <tr className="muted">
        <td>{user.username}</td><td>{roleLabel(user.role)}</td><td>Erased</td><td /><td>{formatDate(user.createdAt)}</td><td />
      </tr>
    );
  }
  return (
    <tr>
      <td>
        <strong>{user.displayName}</strong><br />
        <span className="muted">{user.username}{user.email ? ` · ${user.email}` : ""}</span>
      </td>
      <td>
        <select value={user.role} disabled={self} aria-label={`Role of ${user.username}`}
                onChange={(e) => act(() => api.put(`${path}/role`, { role: e.target.value }))}>
          {ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
        </select>
      </td>
      <td>
        {user.enabled ? "Active" : <span className="badge status-closed">Disabled</span>}
        {user.passwordChangeRequired && <><br /><span className="muted">Temporary password</span></>}
      </td>
      <td>
        {user.mfaEnabled ? "Enrolled" : user.mfaMandatory ? <span className="warn">Not yet enrolled</span> : "Off"}
        {user.role === "REQUESTER" && (
          <label className="check small">
            <input type="checkbox" checked={user.mfaRequired}
                   onChange={(e) => act(() => api.put(`${path}/mfa-required`, { required: e.target.checked }))} />
            required
          </label>
        )}
      </td>
      <td>{formatDate(user.createdAt)}</td>
      <td className="row-actions">
        {!self && (
          <button type="button" className="secondary small"
                  onClick={() => act(() => api.put(`${path}/enabled`, { enabled: !user.enabled }))}>
            {user.enabled ? "Disable" : "Enable"}
          </button>
        )}
        {user.mfaEnabled && (
          <button type="button" className="secondary small"
                  onClick={() => window.confirm(`Remove the second factor of ${user.username}? Their sessions end and they enrol again.`)
                    && act(() => api.post(`${path}/mfa-reset`))}>
            Reset MFA
          </button>
        )}
        {!self && (
          <button type="button" className="secondary small"
                  onClick={() => act(async () => onTemporary(await api.post<TemporaryPasswordView>(`${path}/temporary-password`)))}>
            Temporary password
          </button>
        )}
        {!self && !erasing && (
          <button type="button" className="danger small" onClick={() => setErasing(true)}>Erase…</button>
        )}
        {erasing && (
          <span className="erase">
            <input value={confirmErase} onChange={(e) => setConfirmErase(e.target.value)} placeholder={`type ${user.username}`}
                   aria-label="Type the username to confirm erasure" />
            <button type="button" className="danger small" disabled={confirmErase !== user.username}
                    onClick={() => act(() => api.delete(path))}>Erase data</button>
            <button type="button" className="link" onClick={() => { setErasing(false); setConfirmErase(""); }}>Cancel</button>
          </span>
        )}
      </td>
    </tr>
  );
}

function CreateUser({ onCreated }: { onCreated: (result: TemporaryPasswordView) => void }) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("REQUESTER");
  const [mfaRequired, setMfaRequired] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      onCreated(await api.post<TemporaryPasswordView>("/api/admin/users", {
        username, displayName, email: email || null, role, mfaRequired,
      }));
      setUsername("");
      setDisplayName("");
      setEmail("");
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Card title="New account">
      <form onSubmit={submit} className="filters">
        <label>Username
          <input value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())}
                 pattern="[a-z][a-z0-9._\-]{2,31}" title="3 to 32 characters: a-z, 0-9, dot, dash, underscore" required />
        </label>
        <label>Name
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={100} required />
        </label>
        <label className="grow">Work email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} />
        </label>
        <label>Role
          <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
          </select>
        </label>
        {role === "REQUESTER" && (
          <label className="check">
            <input type="checkbox" checked={mfaRequired} onChange={(e) => setMfaRequired(e.target.checked)} />
            Second factor required
          </label>
        )}
        <button type="submit">Create</button>
      </form>
      <ErrorMessage error={error} />
    </Card>
  );
}
