import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { api, ApiError } from "../../api";
import { ACCEPTED_FILES, MAX_FILE_BYTES } from "../../components/Attachments";
import { Card, ErrorMessage } from "../../components/Bits";
import type { Category, RequesterTicket } from "../../types";

export function NewTicketPage() {
  const navigate = useNavigate();
  const [categories, setCategories] = useState<Category[]>([]);
  const [categoryId, setCategoryId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<Category[]>("/api/categories").then(setCategories).catch(setError);
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const ticket = await api.post<RequesterTicket>("/api/tickets", {
        categoryId: Number(categoryId),
        title,
        description,
      });
      const refused: string[] = [];
      for (const file of files) {
        try {
          await api.upload(`/api/tickets/${ticket.id}/attachments`, file);
        } catch (e) {
          refused.push(`${file.name}: ${e instanceof ApiError ? e.message : "refused"}`);
        }
      }
      navigate(`/tickets/${ticket.id}`, { state: { refused } });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="New ticket">
      <form onSubmit={submit} className="stack wide">
        <ErrorMessage error={error} />
        <label>
          Category
          <select value={categoryId} onChange={(e) => setCategoryId(e.target.value)} required>
            <option value="" disabled>Choose…</option>
            {categories.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label>
          Title
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required />
        </label>
        <label>
          What is the problem?
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={8} maxLength={10000} required />
        </label>
        <label>
          Attachments (PNG, JPEG, PDF or text, up to 10 MB each)
          <input type="file" multiple accept={ACCEPTED_FILES}
                 onChange={(e) => setFiles(Array.from(e.target.files ?? []).filter((f) => f.size <= MAX_FILE_BYTES))} />
        </label>
        <p className="hint">Do not put passwords or other secrets in a ticket.</p>
        <button type="submit" disabled={busy}>File ticket</button>
      </form>
    </Card>
  );
}
