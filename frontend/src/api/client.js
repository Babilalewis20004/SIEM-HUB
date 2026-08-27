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
export const uploadLogs = (formData) =>
  client.post("/logs/upload", formData).then((r) => r.data);

export default client;
