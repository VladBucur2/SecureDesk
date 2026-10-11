import type { TicketPriority, TicketStatus } from "./types";

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatDate(iso: string | null | undefined): string {
  return iso ? dateTime.format(new Date(iso)) : "";
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

const STATUS_LABELS: Record<TicketStatus, string> = {
  NEW: "New",
  IN_PROGRESS: "In progress",
  WAITING_ON_REQUESTER: "Waiting on requester",
  RESOLVED: "Resolved",
  CLOSED: "Closed",
};

export function statusLabel(status: TicketStatus): string {
  return STATUS_LABELS[status];
}

export function priorityLabel(priority: TicketPriority): string {
  return priority.charAt(0) + priority.slice(1).toLowerCase();
}

export function roleLabel(role: string): string {
  return role.charAt(0) + role.slice(1).toLowerCase();
}
