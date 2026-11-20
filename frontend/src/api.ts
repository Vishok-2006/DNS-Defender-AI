import { useEffect, useRef, useState } from 'react';

export interface Alert {
  id: string; domain: string; client_ip: string; category: string; classification: string;
  severity: 'low' | 'medium' | 'high' | 'critical'; status: string; risk_score: number;
  reasons: string[]; occurrences: number; blocked: boolean; last_seen: string;
  analysis?: { summary: string; recommendations: string[]; provider: string } | null;
}
export interface Query {
  id: string; timestamp: string; domain: string; client_ip: string; query_type: string;
  response_code: string; classification: 'benign' | 'suspicious' | 'malicious'; risk_score: number;
  category: string; blocked: boolean;
}
export interface Stats {
  total_queries: number; unique_clients: number; malicious_queries: number; suspicious_queries: number;
  open_alerts: number; blocked_domains: number;
  timeseries: { hour: string; queries: number; alerts: number }[];
  top_domains: { domain: string; count: number }[];
}
export interface Health {
  status: string; model_loaded: boolean; model_version: string; capture_mode: string; auth_required: boolean;
  monitor: { running: boolean; queries_processed: number; last_error: string | null } | null;
}
export interface Prediction {
  classification: string; risk_score: number; category: string; reasons: string[];
  model_prob: number; rule_score: number;
}

const KEY = 'defender_api_key';
const getKey = () => sessionStorage.getItem(KEY) ?? '';

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  if (getKey()) headers['X-API-Key'] = getKey();
  const res = await fetch(`/api/v1${path}`, { ...init, headers });
  if (res.status === 401) {
    const k = window.prompt('This DNS Defender instance requires an API key:');
    if (k) { sessionStorage.setItem(KEY, k); return api<T>(path, init); }
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? res.statusText);
    throw new Error(detail);
  }
  return res.json();
}

export const post = <T = any>(path: string, body?: unknown) =>
  api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

/** WebSocket with automatic reconnect. Returns connection state. */
export function useSocket(path: string, onMessage: (m: any) => void): boolean {
  const [live, setLive] = useState(false);
  const cb = useRef(onMessage);
  cb.current = onMessage;
  useEffect(() => {
    let ws: WebSocket | undefined; let timer: number | undefined; let closed = false; let tries = 0;
    const connect = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const key = getKey() ? `?api_key=${encodeURIComponent(getKey())}` : '';
      ws = new WebSocket(`${proto}://${location.host}${path}${key}`);
      ws.onopen = () => { tries = 0; setLive(true); };
      ws.onmessage = (e) => { try { cb.current(JSON.parse(e.data)); } catch { /* ignore */ } };
      ws.onclose = () => {
        setLive(false);
        if (!closed) timer = window.setTimeout(connect, Math.min(10000, 1000 * 2 ** tries++));
      };
    };
    connect();
    const ping = window.setInterval(() => ws?.readyState === 1 && ws.send('ping'), 25000);
    return () => { closed = true; clearTimeout(timer); clearInterval(ping); ws?.close(); };
  }, [path]);
  return live;
}
