import axios from "axios";

const TOKEN_KEY = "siem_lite_token";

// withCredentials so the browser attaches/accepts the HttpOnly refresh-token
// cookie set by POST /auth/login|register|refresh (see app/routes/auth.py) --
// harmless same-origin in dev (Vite proxies /api to the backend), required
// if frontend/backend ever end up on different origins in production.
const client = axios.create({
  baseURL: "/api",
  withCredentials: true,
});

// Attach the JWT to every outgoing request, if we have one.
client.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A single in-flight refresh promise shared across concurrent 401s, so N
// simultaneous requests trigger one POST /auth/refresh, not N.
let refreshPromise = null;

// Plain axios (not the intercepted `client`) so this call can't recurse
// through the response interceptor below.
export const refreshAccessToken = () =>
  axios.post("/api/auth/refresh", null, { withCredentials: true }).then((r) => {
    setToken(r.data.token);
    return r.data.token;
  });

// A 401 on any request other than the refresh call itself means the access
// token is missing/expired -- try a silent refresh (via the refresh-token
// cookie) and retry the original request once. Only if the refresh itself
// fails do we fall back to clearing the token and forcing a re-login.
client.interceptors.response.use(
  (response) => response,
  (error) => {
    const original = error.config;
    const isRefreshCall = original?.url?.includes("/auth/refresh");

    if (error.response?.status === 401 && !isRefreshCall && !original._retry) {
      original._retry = true;
      refreshPromise = refreshPromise || refreshAccessToken().finally(() => {
        refreshPromise = null;
      });
      return refreshPromise
        .then((newToken) => {
          original.headers.Authorization = `Bearer ${newToken}`;
          return client(original);
        })
        .catch((refreshError) => {
          localStorage.removeItem(TOKEN_KEY);
          window.dispatchEvent(new Event("siem-lite-unauthorized"));
          return Promise.reject(refreshError);
        });
    }

    if (error.response?.status === 401 && isRefreshCall) {
      localStorage.removeItem(TOKEN_KEY);
      window.dispatchEvent(new Event("siem-lite-unauthorized"));
    }

    return Promise.reject(error);
  }
);

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

export const login = (email, password) =>
  client.post("/auth/login", { email, password }).then((r) => r.data);
export const register = (email, password) =>
  client.post("/auth/register", { email, password }).then((r) => r.data);
export const getMe = () => client.get("/auth/me").then((r) => r.data);
// Best-effort: revokes the server-side refresh-token session. Caller clears
// the local access token regardless of whether this succeeds.
export const logout = () => client.post("/auth/logout").catch(() => {});

export const getSummary = () => client.get("/stats/summary").then((r) => r.data);
export const getTimeseries = (hours = 24) =>
  client.get(`/stats/timeseries?hours=${hours}`).then((r) => r.data);
export const getIOCTimeseries = (hours = 24) =>
  client.get(`/stats/ioc-timeseries?hours=${hours}`).then((r) => r.data);

export const getAlerts = (params = {}) =>
  client.get("/alerts", { params }).then((r) => r.data);
export const updateAlert = (id, data) =>
  client.patch(`/alerts/${id}`, data).then((r) => r.data);
export const runDetection = () =>
  client.post("/alerts/run-detection").then((r) => r.data);

export const getMlStatus = () => client.get("/alerts/ml-status").then((r) => r.data);
export const trainModel = (lookbackHours) =>
  client.post("/alerts/train-model", lookbackHours ? { lookback_hours: lookbackHours } : {})
    .then((r) => r.data);

export const getLogs = (params = {}) =>
  client.get("/logs", { params }).then((r) => r.data);
export const getGroupedLogs = (params = {}) =>
  client.get("/logs/grouped", { params }).then((r) => r.data);
export const getLog = (id) =>
  client.get(`/logs/${id}`).then((r) => r.data);
export const uploadLogs = (formData) =>
  client.post("/logs/upload", formData).then((r) => r.data);

export const getUsers = () => client.get("/users").then((r) => r.data);
export const updateUserRole = (id, role) =>
  client.patch(`/users/${id}/role`, { role }).then((r) => r.data);
export const updateUserStatus = (id, is_active) =>
  client.patch(`/users/${id}/status`, { is_active }).then((r) => r.data);

export const getIncidents = (params = {}) =>
  client.get("/incidents", { params }).then((r) => r.data);
export const getIncident = (id) =>
  client.get(`/incidents/${id}`).then((r) => r.data);
export const createIncident = (data) =>
  client.post("/incidents", data).then((r) => r.data);
export const updateIncident = (id, data) =>
  client.patch(`/incidents/${id}`, data).then((r) => r.data);
export const assignIncident = (id, assigned_to) =>
  client.post(`/incidents/${id}/assign`, { assigned_to }).then((r) => r.data);
export const setIncidentStatus = (id, status, reopen = false) =>
  client.post(`/incidents/${id}/status`, { status, reopen }).then((r) => r.data);
export const addIncidentNote = (id, content) =>
  client.post(`/incidents/${id}/notes`, { content }).then((r) => r.data);

export const getMitreTechniques = () =>
  client.get("/mitre/techniques").then((r) => r.data);

export const getIOCs = (params = {}) =>
  client.get("/iocs", { params }).then((r) => r.data);
export const getIOC = (id) =>
  client.get(`/iocs/${id}`).then((r) => r.data);
export const createIOC = (data) =>
  client.post("/iocs", data).then((r) => r.data);
export const updateIOC = (id, data) =>
  client.patch(`/iocs/${id}`, data).then((r) => r.data);
export const deleteIOC = (id) =>
  client.delete(`/iocs/${id}`).then((r) => r.data);
export const enableIOC = (id) =>
  client.post(`/iocs/${id}/enable`).then((r) => r.data);
export const disableIOC = (id) =>
  client.post(`/iocs/${id}/disable`).then((r) => r.data);
export const importIOCs = (iocs) =>
  client.post("/iocs/import", { iocs }).then((r) => r.data);
export const getIOCMatches = (id) =>
  client.get(`/iocs/${id}/matches`).then((r) => r.data);

export const getPlaybooks = () => client.get("/playbooks").then((r) => r.data);
export const getPlaybook = (id) => client.get(`/playbooks/${id}`).then((r) => r.data);
export const getPlaybookActions = () => client.get("/playbooks/actions").then((r) => r.data);
export const createPlaybook = (data) => client.post("/playbooks", data).then((r) => r.data);
export const updatePlaybook = (id, data) => client.patch(`/playbooks/${id}`, data).then((r) => r.data);
export const deletePlaybook = (id) => client.delete(`/playbooks/${id}`).then((r) => r.data);
export const executePlaybook = (id, data = {}) =>
  client.post(`/playbooks/${id}/execute`, data).then((r) => r.data);

export const getPlaybookExecutions = (params = {}) =>
  client.get("/playbook-executions", { params }).then((r) => r.data);
export const getPlaybookExecution = (id) =>
  client.get(`/playbook-executions/${id}`).then((r) => r.data);
export const approveExecution = (id) =>
  client.post(`/playbook-executions/${id}/approve`).then((r) => r.data);
export const rejectExecution = (id, reason) =>
  client.post(`/playbook-executions/${id}/reject`, { reason }).then((r) => r.data);
export const cancelExecution = (id) =>
  client.post(`/playbook-executions/${id}/cancel`).then((r) => r.data);

export default client;
