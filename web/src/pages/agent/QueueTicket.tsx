import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useParams } from "react-router";
import { api } from "../../api";
import { useAuth } from "../../auth";
import { Attachments } from "../../components/Attachments";
import { Card, ErrorMessage, PriorityBadge, Prose, StatusBadge } from "../../components/Bits";
import { formatDate, priorityLabel, statusLabel } from "../../format";
import { PRIORITIES, STATUSES, type AgentTicket, type Person, type TicketPriority, type TicketStatus } from "../../types";

export function QueueTicketPage() {
  const { id } = useParams();
  const { session } = useAuth();
  const base = `/api/queue/${id}`;
  const [ticket, setTicket] = useState<AgentTicket | null>(null);
  const [agents, setAgents] = useState<Person[]>([]);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api.get<AgentTicket>(base).then(setTicket).catch(setError);
  }, [base]);

  useEffect(load, [load]);
  useEffect(() => {
    api.get<Person[]>("/api/queue/agents").then(setAgents).catch(setError);
  }, []);

  if (!ticket) {
    return <Card><ErrorMessage error={error} />{!error && <p>Loading…</p>}</Card>;
  }
  return (
    <div className="columns">
      <Card title={`${ticket.reference} · ${ticket.title}`}>
        <dl className="facts">
          <dt>Requester</dt><dd>{ticket.requester ? `${ticket.requester.displayName} (${ticket.requester.username})` : "Unknown"}</dd>
          <dt>Category</dt><dd>{ticket.category}</dd>
          <dt>Status</dt><dd><StatusBadge status={ticket.status} /></dd>
          <dt>Priority</dt><dd><PriorityBadge priority={ticket.priority} /></dd>
          <dt>Filed</dt><dd>{formatDate(ticket.createdAt)}</dd>
          <dt>Updated</dt><dd>{formatDate(ticket.updatedAt)}</dd>
        </dl>
        <Prose text={ticket.description} />
        <Attachments base={base} items={ticket.attachments} canUpload onUploaded={load} />
      </Card>
      <div className="stack-cards">
        <UpdateForm ticket={ticket} agents={agents} myId={session?.user?.id ?? ""} onSaved={setTicket} />
        <Conversation ticket={ticket} base={base} onSaved={setTicket} />
      </div>
    </div>
  );
}

function UpdateForm({ ticket, agents, myId, onSaved }: {
  ticket: AgentTicket;
  agents: Person[];
  myId: string;
  onSaved: (ticket: AgentTicket) => void;
}) {
  const [status, setStatus] = useState<TicketStatus>(ticket.status);
  const [priority, setPriority] = useState<TicketPriority>(ticket.priority);
  const [assigneeId, setAssigneeId] = useState(ticket.assigneeId ?? "");
  const [resolution, setResolution] = useState(ticket.resolution ?? "");
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setSaved(false);
    try {
      onSaved(await api.put<AgentTicket>(`/api/queue/${ticket.id}`, {
        status,
        priority,
        assigneeId: assigneeId || null,
        resolution: resolution || null,
      }));
      setSaved(true);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Card title="Handle">
      <form onSubmit={submit} className="stack">
        <ErrorMessage error={error} />
        <div className="row">
          <label>Status
            <select value={status} onChange={(e) => setStatus(e.target.value as TicketStatus)}>
              {STATUSES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
            </select>
          </label>
          <label>Priority
            <select value={priority} onChange={(e) => setPriority(e.target.value as TicketPriority)}>
              {PRIORITIES.map((p) => <option key={p} value={p}>{priorityLabel(p)}</option>)}
            </select>
          </label>
        </div>
        <label>Assignee
          <select value={assigneeId} onChange={(e) => setAssigneeId(e.target.value)}>
            <option value="">Unassigned</option>
            {agents.map((a) => <option key={a.id} value={a.id}>{a.displayName}{a.id === myId ? " (me)" : ""}</option>)}
          </select>
        </label>
        <label>Resolution
          <textarea value={resolution} onChange={(e) => setResolution(e.target.value)} rows={3} maxLength={2000} />
        </label>
        <div className="actions">
          {saved && <span className="ok" role="status">Saved</span>}
          {assigneeId !== myId && <button type="button" className="secondary" onClick={() => setAssigneeId(myId)}>Assign to me</button>}
          <button type="submit">Save</button>
        </div>
      </form>
    </Card>
  );
}

function Conversation({ ticket, base, onSaved }: { ticket: AgentTicket; base: string; onSaved: (t: AgentTicket) => void }) {
  const [body, setBody] = useState("");
  const [internal, setInternal] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      onSaved(await api.post<AgentTicket>(`${base}/comments`, { body, internal }));
      setBody("");
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Card title="Conversation and notes">
      {ticket.comments.length === 0 && <p className="empty">No comments yet.</p>}
      <ol className="comments">
        {ticket.comments.map((c) => (
          <li key={c.id} className={c.internal ? "internal" : c.authorRole === "REQUESTER" ? "from-requester" : "from-support"}>
            <div className="meta">
              {c.internal && <span className="badge internal-badge">Internal note</span>} {c.authorName} · {formatDate(c.createdAt)}
            </div>
            <Prose text={c.body} />
          </li>
        ))}
      </ol>
      <form onSubmit={submit} className="stack">
        <ErrorMessage error={error} />
        <label>
          {internal ? "Internal note (agents only)" : "Reply to the requester"}
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={4} maxLength={5000} required
                    className={internal ? "internal-input" : ""} />
        </label>
        <div className="actions">
          <label className="check">
            <input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} />
            Internal note, not visible to the requester
          </label>
          <button type="submit">{internal ? "Add note" : "Send reply"}</button>
        </div>
      </form>
    </Card>
  );
}
