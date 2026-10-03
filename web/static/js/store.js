// Tiny shared state: backend status (polled), used by the header chips and views.
import { api, setServerTime, onStream } from './api.js';

let status = null;
const listeners = new Set();
let timer = null;

export function getStatus() { return status; }
export function onStatus(fn) { listeners.add(fn); if (status) fn(status); return () => listeners.delete(fn); }

export async function refreshStatus() {
  try {
    const s = await api.status();
    status = s;
    setServerTime(s.now);
    for (const fn of listeners) { try { fn(s); } catch (e) { console.error(e); } }
  } catch (e) { /* api.js already reports health */ }
  return status;
}
export function startStatusPolling() {
  refreshStatus();
  clearInterval(timer);
  timer = setInterval(refreshStatus, 10000);
  onStream('alert', () => refreshStatus());
}
