import { useEffect, useRef } from "react";
import * as ws from "../services/websocket.js";

// Subscribes to one WebSocket event type for the lifetime of the component.
// `handler` is read from a ref on every call so passing a fresh inline
// arrow function each render (the common case) doesn't cause a
// resubscribe -- only a change of `eventType` does.
export function useRealtime(eventType, handler) {
  const handlerRef = useRef(handler);

  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    return ws.on(eventType, (...args) => handlerRef.current?.(...args));
  }, [eventType]);
}
