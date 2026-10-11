import type { ReactNode } from "react";
import { ApiError } from "../api";
import { priorityLabel, statusLabel } from "../format";
import type { TicketPriority, TicketStatus } from "../types";

export function StatusBadge({ status }: { status: TicketStatus }) {
  return <span className={`badge status-${status.toLowerCase().replaceAll("_", "-")}`}>{statusLabel(status)}</span>;
}

export function PriorityBadge({ priority }: { priority: TicketPriority }) {
  return <span className={`badge priority-${priority.toLowerCase()}`}>{priorityLabel(priority)}</span>;
}

/** Errors are text. Nothing the API returns is ever rendered as HTML. */
export function ErrorMessage({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof ApiError ? error.message : "Something went wrong.";
  const fields = error instanceof ApiError && error.fields.length > 0 ? ` (${error.fields.join(", ")})` : "";
  return <p className="error" role="alert">{message}{fields}</p>;
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  return (
    <div className="pager">
      <button type="button" className="secondary" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</button>
      <span>Page {page + 1} of {pages} · {total} total</span>
      <button type="button" className="secondary" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** Multi-line user text, shown as text with its line breaks. */
export function Prose({ text }: { text: string }) {
  return <div className="prose">{text}</div>;
}

export function CodeList({ codes }: { codes: string[] }) {
  return (
    <ol className="codes">
      {codes.map((code) => (
        <li key={code}><code>{code}</code></li>
      ))}
    </ol>
  );
}

export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
