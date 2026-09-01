// Single authenticated Socket.IO connection for the whole app -- owned by
// RealtimeContext, never opened per-page/per-component. socket.io-client's
// built-in reconnection already does exponential backoff with jitter
// (reconnectionDelay -> reconnectionDelayMax below matches the 1s..30s
// curve called for in the real-time milestone spec), so this module just
// wires that up to a small status enum ("live" | "reconnecting" | "offline")
// and a plain pub/sub layer other modules can subscribe to without each
// holding their own socket reference.
import { io } from "socket.io-client";

let socket = null;
const eventListeners = new Map(); // eventType -> Set<handler>
const statusListeners = new Set();
let status = "offline";
let authErrorHandler = null;

function setStatus(next) {
  if (status === next) return;
  status = next;
  statusListeners.forEach((fn) => fn(status));
}

export function getStatus() {
  return status;
}

export function onStatusChange(fn) {
  statusListeners.add(fn);
  return () => statusListeners.delete(fn);
}

// `tokenProvider` is a function, not a raw string, so every (re)connection
// attempt reads the *current* access token -- required now that access
// tokens are short-lived (15 min): a refresh that happens via the REST
// interceptor while this socket is open is picked up automatically on the
// socket's next reconnect, with no extra plumbing needed here.
// `onAuthError` (optional) is called on connect_error so the caller can
// proactively trigger a token refresh if the socket drops purely because
// the access token expired with no REST call happening in parallel to
// refresh it first (e.g. a SOC analyst just watching the live feed).
export function connect(tokenProvider, onAuthError) {
  if (socket) disconnect();
  if (!tokenProvider) return null;

  authErrorHandler = onAuthError || null;

  setStatus("reconnecting");
  socket = io("/", {
    path: "/socket.io",
    auth: (cb) => cb({ token: tokenProvider() }),
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 30000,
    randomizationFactor: 0.5,
  });

  socket.on("connect", () => setStatus("live"));
  socket.on("disconnect", (reason) => {
    // A client-initiated disconnect() (e.g. logout) shouldn't show
    // "reconnecting" -- everything else is a dropped connection that
    // socket.io-client will keep retrying in the background.
    setStatus(reason === "io client disconnect" ? "offline" : "reconnecting");
  });
  socket.on("connect_error", () => {
    setStatus("reconnecting");
    authErrorHandler?.();
  });

  for (const [eventType, handlers] of eventListeners) {
    handlers.forEach((handler) => socket.on(eventType, handler));
  }

  return socket;
}

export function disconnect() {
  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
  }
  authErrorHandler = null;
  setStatus("offline");
}

export function on(eventType, handler) {
  if (!eventListeners.has(eventType)) eventListeners.set(eventType, new Set());
  eventListeners.get(eventType).add(handler);
  if (socket) socket.on(eventType, handler);
  return () => off(eventType, handler);
}

export function off(eventType, handler) {
  eventListeners.get(eventType)?.delete(handler);
  if (socket) socket.off(eventType, handler);
}
