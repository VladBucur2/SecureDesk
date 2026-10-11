import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useLocation, useParams } from "react-router";
import { api } from "../../api";
import { Attachments } from "../../components/Attachments";
import { Card, ErrorMessage, PriorityBadge, Prose, StatusBadge } from "../../components/Bits";
import { formatDate } from "../../format";
import type { RequesterTicket } from "../../types";

export function RequesterTicketPage() {
  const { id } = useParams();
  const location = useLocation();
  const refused = (location.state as { refused?: string[] } | null)?.refused ?? [];
  const [ticket, setTicket] = useState<RequesterTicket | null>(null);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const base = `/api/tickets/${id}`;

  const load = useCallback(() => {
    api.get<RequesterTicket>(base).then(setTicket).catch(setError);
  }, [base]);

  useEffect(load, [load]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setTicket(await api.post<RequesterTicket>(`${base}/comments`, { body: comment }));
      setComment("");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (!ticket) {
    return <Card><ErrorMessage error={error} />{!error && <p>Loading…</p>}</Card>;
  }
  const closed = ticket.status === "CLOSED";
  return (
    <div className="columns">
      <Card title={`${ticket.reference} · ${ticket.title}`}>
        {refused.length > 0 && (
          <div className="error" role="alert">
            Some files were not attached:
            <ul>{refused.map((r) => <li key={r}>{r}</li>)}</ul>
          </div>
        )}
        <dl className="facts">
          <dt>Status</dt><dd><StatusBadge status={ticket.status} /></dd>
          <dt>Priority</dt><dd><PriorityBadge priority={ticket.priority} /></dd>
          <dt>Category</dt><dd>{ticket.category}</dd>
          <dt>Handled by</dt><dd>{ticket.assigneeName ?? "Not assigned yet"}</dd>
          <dt>Filed</dt><dd>{formatDate(ticket.createdAt)}</dd>
          {ticket.closedAt && (<><dt>Closed</dt><dd>{formatDate(ticket.closedAt)}</dd></>)}
        </dl>
        <Prose text={ticket.description} />
        {ticket.resolution && (
          <div className="resolution"><h3>Resolution</h3><Prose text={ticket.resolution} /></div>
        )}
        <Attachments base={base} items={ticket.attachments} canUpload={!closed} onUploaded={load} />
      </Card>
      <Card title="Conversation">
        {ticket.comments.length === 0 && <p className="empty">No comments yet.</p>}
        <ol className="comments">
          {ticket.comments.map((c) => (
            <li key={c.id} className={c.fromSupport ? "from-support" : "from-me"}>
              <div className="meta">{c.authorName}{c.fromSupport && " (IT support)"} · {formatDate(c.createdAt)}</div>
              <Prose text={c.body} />
            </li>
          ))}
        </ol>
        <ErrorMessage error={error} />
        {!closed && (
          <form onSubmit={submit} className="stack">
            <label>
              Add a comment
              <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={4} maxLength={5000} required />
            </label>
            <button type="submit" disabled={busy}>Send</button>
          </form>
        )}
        {closed && <p className="muted">This ticket is closed. File a new ticket if the problem returns.</p>}
      </Card>
    </div>
  );
}
