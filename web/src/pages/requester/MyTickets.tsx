import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, query } from "../../api";
import { Card, ErrorMessage, Pager, PriorityBadge, StatusBadge } from "../../components/Bits";
import { formatDate } from "../../format";
import type { Page, TicketSummary } from "../../types";

export function MyTicketsPage() {
  const [page, setPage] = useState(0);
  const [data, setData] = useState<Page<TicketSummary> | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.get<Page<TicketSummary>>(`/api/tickets${query({ page, size: 20 })}`).then(setData).catch(setError);
  }, [page]);

  return (
    <Card title="My tickets" actions={<Link className="button" to="/tickets/new">New ticket</Link>}>
      <ErrorMessage error={error} />
      {data && data.items.length === 0 && <p className="empty">You have not filed any tickets yet.</p>}
      {data && data.items.length > 0 && (
        <>
          <table>
            <thead>
              <tr><th>Ticket</th><th>Title</th><th>Category</th><th>Status</th><th>Priority</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {data.items.map((ticket) => (
                <tr key={ticket.id}>
                  <td><Link to={`/tickets/${ticket.id}`}>{ticket.reference}</Link></td>
                  <td>{ticket.title}</td>
                  <td>{ticket.category}</td>
                  <td><StatusBadge status={ticket.status} /></td>
                  <td><PriorityBadge priority={ticket.priority} /></td>
                  <td>{formatDate(ticket.updatedAt)}</td>
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
