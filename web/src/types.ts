// Shapes of the API's responses. They mirror the DTOs of the Spring Boot API one to one.

export type Role = "REQUESTER" | "AGENT" | "ADMIN";
export type Stage = "ANONYMOUS" | "MFA" | "PASSWORD_CHANGE" | "ENROL" | "AUTHENTICATED";
export type TicketStatus = "NEW" | "IN_PROGRESS" | "WAITING_ON_REQUESTER" | "RESOLVED" | "CLOSED";
export type TicketPriority = "LOW" | "NORMAL" | "HIGH" | "CRITICAL";

export const STATUSES: TicketStatus[] = ["NEW", "IN_PROGRESS", "WAITING_ON_REQUESTER", "RESOLVED", "CLOSED"];
export const PRIORITIES: TicketPriority[] = ["LOW", "NORMAL", "HIGH", "CRITICAL"];

export interface Me {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  mfaEnabled: boolean;
  mfaMandatory: boolean;
  recoveryCodesLeft: number;
}

export interface SessionState {
  stage: Stage;
  user: Me | null;
  pendingUsername: string | null;
  csrfToken: string | null;
}

export interface Page<T> {
  items: T[];
  page: number;
  size: number;
  total: number;
}

export interface Category {
  id: number;
  name: string;
  active: boolean;
}

export interface AttachmentView {
  id: string;
  name: string;
  mediaType: string;
  size: number;
  uploadedBy: string | null;
  createdAt: string;
}

export interface TicketSummary {
  id: string;
  reference: string;
  title: string;
  category: string;
  status: TicketStatus;
  priority: TicketPriority;
  createdAt: string;
  updatedAt: string;
}

export interface PublicComment {
  id: string;
  authorName: string;
  fromSupport: boolean;
  body: string;
  createdAt: string;
}

export interface RequesterTicket {
  id: string;
  reference: string;
  title: string;
  description: string;
  category: string;
  status: TicketStatus;
  priority: TicketPriority;
  assigneeName: string | null;
  resolution: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: PublicComment[];
  attachments: AttachmentView[];
}

export interface QueueItem {
  id: string;
  reference: string;
  title: string;
  category: string;
  status: TicketStatus;
  priority: TicketPriority;
  requesterName: string;
  assigneeId: string | null;
  assigneeName: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Person {
  id: string;
  username: string;
  displayName: string;
}

export interface AgentComment {
  id: string;
  authorName: string;
  authorRole: Role | null;
  internal: boolean;
  body: string;
  createdAt: string;
}

export interface AgentTicket {
  id: string;
  reference: string;
  title: string;
  description: string;
  categoryId: number;
  category: string;
  status: TicketStatus;
  priority: TicketPriority;
  requester: Person | null;
  assigneeId: string | null;
  assigneeName: string | null;
  resolution: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: AgentComment[];
  attachments: AttachmentView[];
}

export interface UserView {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  role: Role;
  enabled: boolean;
  mfaEnabled: boolean;
  mfaMandatory: boolean;
  mfaRequired: boolean;
  passwordChangeRequired: boolean;
  erased: boolean;
  createdAt: string;
}

export interface TemporaryPasswordView {
  user: UserView;
  temporaryPassword: string;
}

export interface Retention {
  months: number;
  maxMonths: number;
}

export interface AuditEntry {
  seq: number;
  eventId: string;
  ts: string;
  event: string;
  category: string;
  outcome: string;
  alert: boolean;
  actorId: string;
  actor: string;
  actorRole: string;
  srcIp: string;
  session: string;
  targetType: string;
  targetId: string;
  correlationId: string;
  details: string;
  hash: string;
}

export interface AuditTypeView {
  name: string;
  category: string;
  alert: boolean;
  purpose: string;
}

export interface ChainResult {
  intact: boolean;
  checkedUpTo: number;
  brokenAt: number;
  reason: string;
}
