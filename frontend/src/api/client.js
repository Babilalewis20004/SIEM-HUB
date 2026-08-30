import axios from "axios";

const TOKEN_KEY = "siem_lite_token";

const client = axios.create({
  baseURL: "/api",
});

// Attach the JWT to every outgoing request, if we have one.
client.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A 401 anywhere means the token is missing/expired/invalid — clear it and
// force a re-login rather than letting the app sit in a broken half-authed state.
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
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

export const getSummary = () => client.get("/stats/summary").then((r) => r.data);
export const getTimeseries = (hours = 24) =>
  client.get(`/stats/timeseries?hours=${hours}`).then((r) => r.data);

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

export default client;
