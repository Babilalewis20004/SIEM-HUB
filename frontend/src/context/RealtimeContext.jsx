import { createContext, useContext, useEffect, useState } from "react";
import { useAuth } from "./AuthContext.jsx";
import { getToken, refreshAccessToken } from "../api/client.js";
import * as ws from "../services/websocket.js";

const RealtimeContext = createContext(null);

// Owns the single Socket.IO connection for the whole app: connects once a
// user is authenticated, disconnects on logout. Access tokens are
// short-lived (15 min) and renew silently via the REST interceptor, so this
// no longer waits for an explicit 401/logout to know something changed --
// ws.connect's tokenProvider re-reads localStorage on every reconnect, and
// its onAuthError callback proactively refreshes if the socket drops purely
// from an expired token with no REST call happening in parallel.
export function RealtimeProvider({ children }) {
  const { user } = useAuth();
  const [status, setStatus] = useState(ws.getStatus());

  useEffect(() => ws.onStatusChange(setStatus), []);

  useEffect(() => {
    if (user) {
      // Pass getToken itself (not its current value) so every reconnection
      // attempt re-reads localStorage -- picks up a token silently refreshed
      // by the REST interceptor without this effect needing to re-run.
      ws.connect(getToken, () => refreshAccessToken().catch(() => {}));
    } else {
      ws.disconnect();
    }
  }, [user]);

  return <RealtimeContext.Provider value={{ status }}>{children}</RealtimeContext.Provider>;
}

export function useRealtimeStatus() {
  const ctx = useContext(RealtimeContext);
  if (!ctx) throw new Error("useRealtimeStatus must be used within a RealtimeProvider");
  return ctx.status;
}
