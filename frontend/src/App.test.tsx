// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import App from './App';

const alert = {
  id: 'a1', domain: 'xk910zp2a88q093.biz', client_ip: '192.168.1.144', category: 'DGA (algorithmically generated domain)',
  classification: 'malicious', severity: 'high', status: 'new', risk_score: 0.91, reasons: ['Name looks algorithmically generated'],
  occurrences: 3, blocked: false, last_seen: '2026-11-14T10:00:00Z', analysis: null,
};
const routes: Record<string, unknown> = {
  '/api/v1/health': { status: 'healthy', model_loaded: true, model_version: 'rf', capture_mode: 'off', auth_required: false, monitor: null },
  '/api/v1/stats': { total_queries: 1234, unique_clients: 7, malicious_queries: 5, suspicious_queries: 2, open_alerts: 1, blocked_domains: 1,
    timeseries: [{ hour: '2026-11-14T09:00:00Z', queries: 10, alerts: 1 }], top_domains: [{ domain: 'github.com', count: 4 }] },
  '/api/v1/alerts?limit=30': { alerts: [alert] },
  '/api/v1/queries?limit=30': { queries: [{ id: 'q1', timestamp: '2026-11-14T10:00:00Z', domain: 'github.com', client_ip: '192.168.1.5',
    query_type: 'A', response_code: 'NOERROR', classification: 'benign', risk_score: 0.01, category: 'Benign', blocked: false }] },
  '/api/v1/domains/blocklist': { blocked_domains: [{ domain: 'evil.example', reason: 'x' }] },
};
const calls: { url: string; method?: string; body?: string }[] = [];

class FakeWS { static instances: FakeWS[] = []; readyState = 0; onopen?: () => void; onmessage?: (e: { data: string }) => void; onclose?: () => void;
  constructor(public url: string) { FakeWS.instances.push(this); setTimeout(() => { this.readyState = 1; this.onopen?.(); }); }
  send() {} close() { this.readyState = 3; } }

beforeEach(() => {
  calls.length = 0; FakeWS.instances = [];
  vi.stubGlobal('WebSocket', FakeWS);
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method, body: init?.body as string });
    if (url === '/api/v1/dns/test-query') return { ok: true, status: 200, json: async () => ({ prediction: { classification: 'malicious', risk_score: 0.93, category: 'DGA', reasons: ['why'], model_prob: 0.93, rule_score: 0 } }) };
    return { ok: url in routes || init?.method === 'POST', status: 200, json: async () => routes[url] ?? { success: true } };
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test('renders stats, alerts, traffic and blocklist from the API', async () => {
  render(<App />);
  await waitFor(() => expect(screen.getByText('1234')).toBeTruthy());
  expect(screen.getAllByText('xk910zp2a88q093.biz').length).toBeGreaterThan(0);
  expect(screen.getAllByText('github.com').length).toBeGreaterThan(0);
  expect(screen.getByText('evil.example')).toBeTruthy();
  expect(screen.getByText(/Random Forest/)).toBeTruthy();
});

test('checking a domain posts to the API and shows the verdict', async () => {
  render(<App />);
  await waitFor(() => screen.getByText('Analyse'));
  fireEvent.click(screen.getByText('Analyse'));
  await waitFor(() => expect(screen.getByText(/MALICIOUS — risk 93%/)).toBeTruthy());
  const post = calls.find((c) => c.url === '/api/v1/dns/test-query')!;
  expect(post.method).toBe('POST'); expect(JSON.parse(post.body!).domain).toBe('xk910zp2a88q093.biz');
});

test('block button calls the block endpoint; live websocket rows appear', async () => {
  render(<App />);
  await waitFor(() => screen.getByText('Block'));
  fireEvent.click(screen.getByText('Block'));
  await waitFor(() => expect(calls.some((c) => c.url === '/api/v1/domains/block')).toBe(true));
  const traffic = FakeWS.instances.find((w) => w.url.includes('/ws/traffic'))!;
  traffic.onmessage?.({ data: JSON.stringify({ event: 'dns_query', data: { id: 'live1', timestamp: '2026-11-14T10:01:00Z', domain: 'live-domain.example',
    client_ip: '1.1.1.1', query_type: 'A', response_code: 'NOERROR', classification: 'benign', risk_score: 0.1, category: 'Benign', blocked: false } }) });
  await waitFor(() => expect(screen.getByText('live-domain.example')).toBeTruthy());
});

test('shows an error banner when the backend is down', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('boom'); }));
  render(<App />);
  await waitFor(() => expect(screen.getByText(/Backend unreachable/)).toBeTruthy());
});
