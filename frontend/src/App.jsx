import { BrowserRouter, Routes, Route, NavLink, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Alerts from "./pages/Alerts.jsx";
import Logs from "./pages/Logs.jsx";
import Login from "./pages/Login.jsx";

function AppShell() {
  const { user, loading, logout } = useAuth();

  if (loading) {
    return <div className="auth-shell"><p>Loading…</p></div>;
  }

  if (!user) {
    return <Login />;
  }

  return (
    <div className="app-shell">
      <nav className="sidebar">
        <h1 className="brand">SIEM-HUB</h1>
        <NavLink to="/" end className="nav-link">Dashboard</NavLink>
        <NavLink to="/alerts" className="nav-link">Alerts</NavLink>
        <NavLink to="/logs" className="nav-link">Logs</NavLink>

        <div className="sidebar-footer">
          <div className="user-chip">
            <span className="user-email">{user.email}</span>
            <span className="user-role">{user.role}</span>
          </div>
          <button className="logout-btn" onClick={logout}>Sign Out</button>
        </div>
      </nav>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppShell />
      </AuthProvider>
    </BrowserRouter>
  );
}
