import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api } from "../../api";
import { Card, ErrorMessage } from "../../components/Bits";
import type { Category, Retention } from "../../types";

/** UC-06: categories. */
export function CategoriesPage() {
  const [categories, setCategories] = useState<Category[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api.get<Category[]>("/api/admin/categories").then(setCategories).catch(setError);
  }, []);
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

  const add = (event: FormEvent) => {
    event.preventDefault();
    act(async () => {
      await api.post("/api/admin/categories", { name });
      setName("");
    });
  };

  return (
    <Card title="Ticket categories">
      <ErrorMessage error={error} />
      <table>
        <thead><tr><th>Name</th><th>State</th><th /></tr></thead>
        <tbody>
          {categories.map((c) => (
            <CategoryRow key={c.id} category={c}
                         onSave={(newName, active) => act(() => api.put(`/api/admin/categories/${c.id}`, { name: newName, active }))} />
          ))}
        </tbody>
      </table>
      <form onSubmit={add} className="filters">
        <label className="grow">New category
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} required />
        </label>
        <button type="submit">Add</button>
      </form>
    </Card>
  );
}

function CategoryRow({ category, onSave }: { category: Category; onSave: (name: string, active: boolean) => void }) {
  const [name, setName] = useState(category.name);
  return (
    <tr className={category.active ? "" : "muted"}>
      <td><input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} aria-label="Category name" /></td>
      <td>{category.active ? "Active" : "Inactive"}</td>
      <td className="row-actions">
        <button type="button" className="secondary small" disabled={name === category.name || !name.trim()}
                onClick={() => onSave(name, category.active)}>Rename</button>
        <button type="button" className="secondary small" onClick={() => onSave(category.name, !category.active)}>
          {category.active ? "Deactivate" : "Activate"}
        </button>
      </td>
    </tr>
  );
}

/** UC-06 and SR-10: the retention period is a privacy control; changing it is an alerted audit event. */
export function RetentionPage() {
  const [retention, setRetention] = useState<Retention | null>(null);
  const [months, setMonths] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.get<Retention>("/api/admin/settings/retention").then((r) => {
      setRetention(r);
      setMonths(String(r.months));
    }).catch(setError);
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setResult(null);
    try {
      setRetention(await api.put<Retention>("/api/admin/settings/retention", { months: Number(months) }));
      setResult("Saved.");
    } catch (e) {
      setError(e);
    }
  };

  const runNow = async () => {
    setError(null);
    setResult(null);
    try {
      const outcome = await api.post<{ deleted: number }>("/api/admin/settings/retention/run");
      setResult(`${outcome.deleted} closed ticket(s) deleted.`);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Card title="Retention of closed tickets">
      <p>
        Closed tickets, with their comments and attachments, are deleted automatically once they have been
        closed for longer than this period. The check runs every night.
      </p>
      <ErrorMessage error={error} />
      {retention && (
        <form onSubmit={save} className="filters">
          <label>Months
            <input type="number" min={1} max={retention.maxMonths} value={months} onChange={(e) => setMonths(e.target.value)} required />
          </label>
          <span className="muted">At most {retention.maxMonths} months, set by the operator.</span>
          <button type="submit">Save</button>
          <button type="button" className="secondary" onClick={runNow}>Run now</button>
        </form>
      )}
      {result && <p className="ok" role="status">{result}</p>}
    </Card>
  );
}
