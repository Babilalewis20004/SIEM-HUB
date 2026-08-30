import { createContext, useContext, useMemo } from "react";
import { useAuth } from "./AuthContext.jsx";
import { roleCan } from "../auth/permissions.js";

const PermissionContext = createContext(null);

export function PermissionProvider({ children }) {
  const { user } = useAuth();

  const value = useMemo(() => ({
    role: user?.role ?? null,
    can: (permission) => (user ? roleCan(user.role, permission) : false),
  }), [user]);

  return <PermissionContext.Provider value={value}>{children}</PermissionContext.Provider>;
}

export function usePermissions() {
  const ctx = useContext(PermissionContext);
  if (!ctx) throw new Error("usePermissions must be used within a PermissionProvider");
  return ctx;
}
