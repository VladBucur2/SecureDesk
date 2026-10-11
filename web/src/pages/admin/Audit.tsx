import { Fragment, useEffect, useMemo, useState } from "react";
import { api, query } from "../../api";
import { Card, ErrorMessage, Pager } from "../../components/Bits";
import { formatDate } from "../../format";
import type { AuditEntry, AuditTypeView, ChainResult, Page } from "../../types";

/**
 * UC-07. Entries are data: every field is rendered as text by React, so a string an attacker
 * managed to get into the trail cannot run in the administrator's browser. Reading this page is
 * itself an audit event.
 */
export function AuditPage() {
  const [types, setTypes] = useState<AuditTypeView[]>([]);
  const [type, setType] = useState("");
  const [category, setCategory] = useState("");
  const [actor, setActor] = useState("");
  const [alertOnly, setAlertOnly] = useState(false);
  const [filter, setFilter] = useState({ type: "", category: "", actor: "", alertOnly: false });
  const [page, setPage] = useState(0);
  const [data, setData] = useState<Page<AuditEntry> | null>(null);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.get<AuditTypeView[]>("/api/admin/audit/types").then(setTypes).catch(setError);
  }, []);

  useEffect(() => {
    api.get<Page<AuditEntry>>(`/api/admin/audit${query({ ...filter, actor: filter.actor || null, page, size: 50 })}`)
      .then(setData).catch(setError);
  }, [filter, page]);

  const categories = useMemo(() => Array.from(new Set(types.map((t) => t.category))).sort(), [types]);
  const purpose = useMemo(() => new Map(types.map((t) => [t.name, t.purpose])), [types]);

  const verify = async () => {
    setError(null);
    try {
      setChain(await api.post<ChainResult>("/api/admin/audit/verify"));
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Card title="Audit log" actions={<button type="button" className="secondary" onClick={verify}>Verify hash chain</button>}>
      {chain && (
        <p className={chain.intact ? "banner ok" : "banner danger"} role="status">
          {chain.intact
            ? `Hash chain intact up to entry ${chain.checkedUpTo}.`
            : `Hash chain broken at entry ${chain.brokenAt}: ${chain.reason}.`}
        </p>
      )}
      <form className="filters" onSubmit={(e) => { e.preventDefault(); setFilter({ type, category, actor, alertOnly }); setPage(0); }}>
        <label>Event
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">Any</option>
            {types.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
          </select>
        </label>
        <label>Category
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">Any</option>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label>Actor
          <input value={actor} onChange={(e) => setActor(e.target.value.toLowerCase())} maxLength={64} />
        </label>
        <label className="check">
          <input type="checkbox" checked={alertOnly} onChange={(e) => setAlertOnly(e.target.checked)} />
          Alerts only
        </label>
        <button type="submit" className="secondary">Filter</button>
      </form>
      <ErrorMessage error={error} />
      {data && (
        <>
          <table className="audit">
            <thead>
              <tr><th>#</th><th>Time (local)</th><th>Event</th><th>Outcome</th><th>Actor</th><th>Source</th><th>Target</th></tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <Fragment key={e.seq}>
                  <tr className={e.alert ? "alert-row" : ""} onClick={() => setOpen(open === e.seq ? null : e.seq)}>
                    <td>{e.seq}</td>
                    <td>{formatDate(e.ts)}</td>
                    <td title={purpose.get(e.event)}>{e.alert && <span className="badge alert-badge">alert</span>} {e.event}</td>
                    <td>{e.outcome}</td>
                    <td>{e.actor}{e.actorRole !== "-" && <span className="muted"> ({e.actorRole.toLowerCase()})</span>}</td>
                    <td>{e.srcIp}</td>
                    <td>{e.targetType !== "-" ? `${e.targetType} ${e.targetId.slice(0, 8)}` : ""}</td>
                  </tr>
                  {open === e.seq && (
                    <tr className="detail-row">
                      <td colSpan={7}>
                        <dl className="facts">
                          <dt>Details</dt><dd><code>{e.details}</code></dd>
                          <dt>Session</dt><dd><code>{e.session}</code></dd>
                          <dt>Correlation id</dt><dd><code>{e.correlationId}</code></dd>
                          <dt>Target</dt><dd><code>{e.targetType} {e.targetId}</code></dd>
                          <dt>Entry hash</dt><dd><code>{e.hash}</code></dd>
                          <dt>Time (UTC)</dt><dd><code>{e.ts}</code></dd>
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <Pager page={data.page} size={data.size} total={data.total} onPage={setPage} />
        </>
      )}
    </Card>
  );
}
