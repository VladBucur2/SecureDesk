import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError, onStepUpRequired } from "../api";

/**
 * Step-up authentication (UC-05): when the API answers an administrative request with
 * "reauth_required", this dialog asks for a fresh code from the authenticator, confirms it with
 * /api/auth/reauth, and lets the original request be retried. Cancelling rejects the request.
 */
export function StepUpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const pending = useRef<{ resolve: () => void; reject: (e: Error) => void } | null>(null);

  const ask = useCallback(
    () =>
      new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject };
        setOpen(true);
      }),
    [],
  );

  useEffect(() => {
    onStepUpRequired(ask);
    return () => onStepUpRequired(null);
  }, [ask]);

  const finish = (error?: Error) => {
    setOpen(false);
    const current = pending.current;
    pending.current = null;
    if (error) current?.reject(error);
    else current?.resolve();
  };

  return (
    <>
      {children}
      {open && <StepUpDialog onDone={() => finish()} onCancel={() => finish(new ApiError(403, "reauth_cancelled", "Cancelled."))} />}
    </>
  );
}

function StepUpDialog({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.auth("/api/auth/reauth", { code: code.trim() });
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dialog-backdrop" role="presentation">
      <form className="dialog" role="dialog" aria-modal="true" aria-labelledby="stepup-title" onSubmit={submit}>
        <h2 id="stepup-title">Confirm it is you</h2>
        <p>This change needs a recent sign-in. Enter the current code from your authenticator app.</p>
        {error && <p className="error" role="alert">{error}</p>}
        <label>
          Six-digit code
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            autoFocus
          />
        </label>
        <div className="actions">
          <button type="button" className="secondary" onClick={onCancel}>Cancel</button>
          <button type="submit" disabled={busy}>Confirm</button>
        </div>
      </form>
    </div>
  );
}
