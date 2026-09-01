import { createContext, useContext, useEffect, useState, useCallback } from "react";
import {
  login as apiLogin,
  register as apiRegister,
  logout as apiLogout,
  getMe,
  setToken as persistToken,
  clearToken,
} from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadCurrentUser = useCallback(async () => {
    // Always attempt this, even with no access token in localStorage --
    // a 401 here (missing/expired access token) triggers the axios
    // interceptor's silent refresh via the HttpOnly refresh-token cookie,
    // so a still-valid 7-day session survives a page reload with no
    // forced re-login. Only a failed refresh (or no cookie at all) lands
    // in the catch below.
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      clearToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrentUser();

    // Fired by the axios interceptor on any 401 response.
    const onUnauthorized = () => setUser(null);
    window.addEventListener("siem-lite-unauthorized", onUnauthorized);
    return () => window.removeEventListener("siem-lite-unauthorized", onUnauthorized);
  }, [loadCurrentUser]);

  const login = async (email, password) => {
    const { token, user: loggedInUser } = await apiLogin(email, password);
    persistToken(token);
    setUser(loggedInUser);
    return loggedInUser;
  };

  const register = async (email, password) => {
    const { token, user: newUser } = await apiRegister(email, password);
    persistToken(token);
    setUser(newUser);
    return newUser;
  };

  const logout = async () => {
    await apiLogout();
    clearToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
