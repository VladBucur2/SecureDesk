import { useRef, useState } from "react";
import { api } from "../api";
import { formatDate, formatSize } from "../format";
import type { AttachmentView } from "../types";
import { ErrorMessage } from "./Bits";

export const ACCEPTED_FILES = ".png,.jpg,.jpeg,.pdf,.txt,.log";
export const MAX_FILE_BYTES = 10 * 1024 * 1024;

/**
 * Attachments are plain links to the API, which serves them with Content-Disposition: attachment.
 * They are never shown inline in SecureDesk's own origin.
 */
export function Attachments({ base, items, canUpload, onUploaded }: {
  base: string;
  items: AttachmentView[];
  canUpload: boolean;
  onUploaded: () => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const upload = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await api.upload(`${base}/attachments`, file);
      onUploaded();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };

  return (
    <div className="attachments">
      <h3>Attachments</h3>
      {items.length === 0 && <p className="empty">None.</p>}
      <ul>
        {items.map((a) => (
          <li key={a.id}>
            <a href={`${base}/attachments/${a.id}`} download>{a.name}</a>
            <span className="muted"> · {formatSize(a.size)} · {a.uploadedBy ?? ""} · {formatDate(a.createdAt)}</span>
          </li>
        ))}
      </ul>
      <ErrorMessage error={error} />
      {canUpload && (
        <label className="upload">
          Add a file (PNG, JPEG, PDF or text, up to 10 MB)
          <input ref={input} type="file" accept={ACCEPTED_FILES} disabled={busy}
                 onChange={(e) => upload(e.target.files?.[0])} />
        </label>
      )}
    </div>
  );
}
