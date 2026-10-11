// The only place that talks to the API.
//
// - Same origin only, with the session cookie (HttpOnly, Secure, SameSite=Strict); the front end
//   never sees the session id.
// - The CSRF synchroniser token comes from /api/auth/session and is kept in memory only, never in
//   localStorage, and sent as X-XSRF-TOKEN on every state-changing request.
// - A 403 "reauth_required" opens the step-up dialog and retries the request once afterwards.

import type { SessionState } from "./types";

let csrfToken: string | null = null;
let stepUpHandler: (() => Promise<void>) | null = null;
let sessionEndedHandler: (() => void) | null = null;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly fields: string[] = [],
  ) {
    super(message);
  }
}

export function onStepUpRequired(handler: (() => Promise<void>) | null) {
  stepUpHandler = handler;
}

export function onSessionEnded(handler: (() => void) | null) {
  sessionEndedHandler = handler;
}

interface Options {
  retried?: boolean;
  /** Sign-in endpoints answer 401 for a wrong password; that is not "your session ended". */
  authFlow?: boolean;
}

async function request<T>(method: string, path: string, body?: unknown, options: Options = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET" && csrfToken) {
    headers["X-XSRF-TOKEN"] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: payload,
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  });

  if (response.status === 204) {
    return undefined as T;
  }
  const data = response.headers.get("Content-Type")?.includes("application/json")
    ? await response.json().catch(() => null)
    : null;

  if (response.ok) {
    return data as T;
  }

  const error = new ApiError(
    response.status,
    data?.error ?? "error",
    data?.message ?? "Something went wrong.",
    data?.fields ?? [],
  );

  if (!options.retried && error.code === "reauth_required" && stepUpHandler) {
    await stepUpHandler();
    return request<T>(method, path, body, { ...options, retried: true });
  }
  if (!options.retried && error.code === "csrf") {
    // The session changed under us (for instance it was rotated); fetch the new token and retry once.
    await getSession();
    return request<T>(method, path, body, { ...options, retried: true });
  }
  if (response.status === 401 && !options.authFlow && sessionEndedHandler) {
    sessionEndedHandler();
  }
  throw error;
}

export async function getSession(): Promise<SessionState> {
  const state = await request<SessionState>("GET", "/api/auth/session");
  csrfToken = state.csrfToken;
  return state;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
  upload: <T>(path: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<T>("POST", path, form);
  },
  /** Sign-in steps: a 401 here means "not correct", handled by the page itself. */
  auth: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}, { authFlow: true }),
};

export function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== "") {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
