import { createContext, useContext, useEffect, useState } from "react";
import { useAuth } from "./AuthContext.jsx";
import { getToken } from "../api/client.js";
import * as ws from "../services/websocket.js";

const RealtimeContext = createContext(null);

// Owns the single Socket.IO connection for the whole app: connects once a
// user is authenticated, disconnects on logout, and reconnects with a new
// token if the user logs in again. A REST 401 (expired/invalid token)
// already clears `user` via AuthContext's siem-lite-unauthorized listener,
// which this effect reacts to the same way as an explicit logout -- the
// socket doesn't need its own separate expiry detection.
export function RealtimeProvider({ children }) {
  const { user } = useAuth();
  const [status, setStatus] = useState(ws.getStatus());

  useEffect(() => ws.onStatusChange(setStatus), []);

  useEffect(() => {
    if (user) {
      ws.connect(getToken());
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
