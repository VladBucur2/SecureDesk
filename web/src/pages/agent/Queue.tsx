import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, query } from "../../api";
import { Card, ErrorMessage, Pager, PriorityBadge, StatusBadge } from "../../components/Bits";
import { formatDate, statusLabel } from "../../format";
import { STATUSES, type Category, type Page, type QueueItem } from "../../types";

export function QueuePage() {
  const [status, setStatus] = useState("");
  const [categoryId, setCategoryId] = useState("");
  const [assignee, setAssignee] = useState("any");
  const [search, setSearch] = useState("");
  const [submittedSearch, setSubmittedSearch] = useState("");
  const [page, setPage] = useState(0);
  const [categories, setCategories] = useState<Category[]>([]);
  const [data, setData] = useState<Page<QueueItem> | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.get<Category[]>("/api/categories").then(setCategories).catch(setError);
  }, []);

  useEffect(() => {
    api.get<Page<QueueItem>>(`/api/queue${query({ status, categoryId, assignee, q: submittedSearch, page, size: 25 })}`)
      .then(setData).catch(setError);
  }, [status, categoryId, assignee, submittedSearch, page]);

  const reset = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(0);
  };

  return (
    <Card title="Queue">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); setSubmittedSearch(search); setPage(0); }}>
        <label>Status
          <select value={status} onChange={(e) => reset(setStatus)(e.target.value)}>
            <option value="">Any</option>
            {STATUSES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
          </select>
        </label>
        <label>Category
          <select value={categoryId} onChange={(e) => reset(setCategoryId)(e.target.value)}>
            <option value="">Any</option>
            {categories.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label>Assigned to
          <select value={assignee} onChange={(e) => reset(setAssignee)(e.target.value)}>
            <option value="any">Anyone</option>
            <option value="me">Me</option>
            <option value="none">Nobody</option>
          </select>
        </label>
        <label className="grow">Search titles
          <input value={search} onChange={(e) => setSearch(e.target.value)} maxLength={100} />
        </label>
        <button type="submit" className="secondary">Search</button>
      </form>
      <ErrorMessage error={error} />
      {data && data.items.length === 0 && <p className="empty">No tickets match.</p>}
      {data && data.items.length > 0 && (
        <>
          <table>
            <thead>
              <tr><th>Ticket</th><th>Title</th><th>Requester</th><th>Category</th><th>Status</th><th>Priority</th><th>Assignee</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {data.items.map((t) => (
                <tr key={t.id}>
                  <td><Link to={`/queue/${t.id}`}>{t.reference}</Link></td>
                  <td>{t.title}</td>
                  <td>{t.requesterName}</td>
                  <td>{t.category}</td>
                  <td><StatusBadge status={t.status} /></td>
                  <td><PriorityBadge priority={t.priority} /></td>
                  <td>{t.assigneeName ?? <span className="muted">Unassigned</span>}</td>
                  <td>{formatDate(t.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={data.page} size={data.size} total={data.total} onPage={setPage} />
        </>
      )}
    </Card>
  );
}
