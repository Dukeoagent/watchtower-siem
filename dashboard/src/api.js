/**
 * WatchTower SIEM - API Client
 * All HTTP calls to the FastAPI backend live here.
 * Components just call these functions — no raw fetch anywhere else.
 *
 * In production, the dashboard is served by nginx which proxies
 *   /api/  -> backend:8000/api/
 *   /ws/   -> backend:8000/ws/
 * In dev (vite dev server), vite.config.js does the same proxying.
 * So we use relative paths for both HTTP and WebSocket.
 */

async function get(path) {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

async function post(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

export const api = {
  // Dashboard stats
  getStats:         ()          => get('/api/stats'),
  // Alerts
  getAlerts:        (params='') => get(`/api/alerts${params}`),
  getAlert:         (id)        => get(`/api/alerts/${id}`),
  // Agents
  getAgents:        ()          => get('/api/agents'),
  // ATT&CK heatmap
  getTTPHeatmap:    ()          => get('/api/ttp-heatmap'),
  // FIM
  getFIMEvents:     (agent='')  => get(`/api/fim${agent ? `?agent=${agent}` : ''}`),
  // Notifications
  getNotifyConfig:  ()          => get('/api/notify/config'),
  saveNotifyConfig: (cfg)       => post('/api/notify/config', cfg),
  sendTestEmail:    ()          => post('/api/notify/test', {}),
  // Demo: trigger a fake alert from the visitor's location
  triggerDemoAlert: (severity)  => post(`/api/demo/alert?severity=${severity}`, {}),
  // Health
  health:           ()          => get('/health'),
};

/** Open a WebSocket to receive real-time alerts. */
export function openAlertSocket(onAlert) {
  // Build wss:// for https pages, ws:// for http. Same host as the page.
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${proto}//${window.location.host}/ws/alerts`;

  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (e) {
    console.warn('WebSocket init failed:', e);
    return { close: () => {} };
  }

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'new_alert') onAlert(msg.alert);
    } catch {}
  };

  ws.onerror = () => console.warn('WebSocket error - live alerts unavailable');

  return ws;
}
