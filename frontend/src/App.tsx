import { Fragment, useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { api, post, useSocket, type Alert, type Health, type Prediction, type Query, type Stats } from './api';

const SEV: Record<string, string> = {
  critical: 'bg-red-600 text-white', high: 'bg-orange-500 text-black',
  medium: 'bg-yellow-400 text-black', low: 'bg-sky-500 text-black',
};
const CLS: Record<string, string> = {
  malicious: 'text-red-400', suspicious: 'text-yellow-300', benign: 'text-emerald-400',
};

const Card = ({ title, right, children }: { title: string; right?: ReactNode; children: ReactNode }) => (
  <section className="rounded-lg border border-slate-700/60 bg-slate-900/70 p-4">
    <div className="mb-3 flex items-center justify-between">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-300">{title}</h2>{right}
    </div>
    {children}
  </section>
);
const Stat = ({ label, value, tone = '' }: { label: string; value: number | string; tone?: string }) => (
  <div className="rounded-lg border border-slate-700/60 bg-slate-900/70 p-4">
    <div className="text-xs uppercase text-slate-400">{label}</div>
    <div className={`mt-1 text-2xl font-bold ${tone}`}>{value}</div>
  </div>
);
const Pill = ({ ok, label }: { ok: boolean; label: string }) => (
  <span className={`rounded-full px-2 py-0.5 text-xs ${ok ? 'bg-emerald-900 text-emerald-300' : 'bg-red-900 text-red-300'}`}>
    {ok ? '●' : '○'} {label}
  </span>
);
const btn = 'rounded bg-slate-700 px-2 py-1 text-xs hover:bg-slate-600 disabled:opacity-40';
const time = (iso: string) => new Date(iso).toLocaleTimeString();

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [queries, setQueries] = useState<Query[]>([]);
  const [blocked, setBlocked] = useState<{ domain: string; reason: string }[]>([]);
  const [error, setError] = useState('');
  const [domain, setDomain] = useState('xk910zp2a88q093.biz');
  const [nx, setNx] = useState(false);
  const [result, setResult] = useState<Prediction | null>(null);
  const [busy, setBusy] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [h, s, a, q, b] = await Promise.all([
        api<Health>('/health'), api<Stats>('/stats'), api('/alerts?limit=30'),
        api('/queries?limit=30'), api('/domains/blocklist'),
      ]);
      setHealth(h); setStats(s); setAlerts(a.alerts); setQueries(q.queries); setBlocked(b.blocked_domains);
      setError('');
    } catch (e) { setError(`Backend unreachable: ${(e as Error).message}`); }
  }, []);

  useEffect(() => { refresh(); const t = setInterval(refresh, 15000); return () => clearInterval(t); }, [refresh]);

  const debounce = useRef<number | undefined>(undefined);
  const soon = () => { clearTimeout(debounce.current); debounce.current = window.setTimeout(refresh, 400); };
  const liveTraffic = useSocket('/ws/traffic', (m) => {
    if (m.event === 'dns_query') setQueries((p) => [m.data as Query, ...p].slice(0, 30));
  });
  const liveAlerts = useSocket('/ws/alerts', (m) => { if (m.event === 'alert') soon(); });

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label); setError('');
    try { await fn(); await refresh(); } catch (e) { setError((e as Error).message); } finally { setBusy(''); }
  };

  const check = () => run('check', async () => {
    const r = await post('/dns/test-query', { domain, response_code: nx ? 'NXDOMAIN' : 'NOERROR' });
    setResult(r.prediction);
  });

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold">🛡️ DNS Defender AI</h1>
          <p className="text-xs text-slate-400">AI-powered DNS behaviour analysis for malicious domain detection</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Pill ok={health?.status === 'healthy'} label="API" />
          <Pill ok={!!health?.model_loaded} label={health?.model_loaded ? 'Random Forest' : 'Model missing – heuristic mode'} />
          <Pill ok={liveTraffic && liveAlerts} label="Live feed" />
          {health?.monitor && <Pill ok={health.monitor.running && !health.monitor.last_error} label="DNS monitor" />}
        </div>
      </header>

      {error && <div className="rounded border border-red-700 bg-red-950 p-2 text-sm text-red-300">{error}</div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Queries (24h)" value={stats?.total_queries ?? '–'} />
        <Stat label="Clients" value={stats?.unique_clients ?? '–'} />
        <Stat label="Open alerts" value={stats?.open_alerts ?? '–'} tone="text-yellow-300" />
        <Stat label="Malicious" value={stats?.malicious_queries ?? '–'} tone="text-red-400" />
        <Stat label="Blocked domains" value={stats?.blocked_domains ?? '–'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2"><Card title="DNS queries & alerts per hour">
          <div className="h-56"><ResponsiveContainer>
            <AreaChart data={(stats?.timeseries ?? []).map((p) => ({ ...p, h: new Date(p.hour).getHours() + ':00' }))}>
              <CartesianGrid stroke="#334155" strokeDasharray="3 3" />
              <XAxis dataKey="h" stroke="#94a3b8" fontSize={11} /><YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Area dataKey="queries" stroke="#38bdf8" fill="#0ea5e955" />
              <Area dataKey="alerts" stroke="#f87171" fill="#ef444488" />
            </AreaChart></ResponsiveContainer></div>
        </Card></div>
        <Card title="Top domains">
          <div className="h-56"><ResponsiveContainer>
            <BarChart data={stats?.top_domains ?? []} layout="vertical" margin={{ left: 30 }}>
              <XAxis type="number" stroke="#94a3b8" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="domain" stroke="#94a3b8" fontSize={10} width={110} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Bar dataKey="count" fill="#818cf8" />
            </BarChart></ResponsiveContainer></div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Check a domain">
          <div className="space-y-2">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && check()}
              className="w-full rounded border border-slate-600 bg-slate-950 px-2 py-1 font-mono text-sm" placeholder="example.com" />
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input type="checkbox" checked={nx} onChange={(e) => setNx(e.target.checked)} /> Response was NXDOMAIN
            </label>
            <button className={btn} disabled={!domain || busy === 'check'} onClick={check}>Analyse</button>
            {result && (
              <div className="rounded border border-slate-700 p-2 text-sm">
                <div className={`font-bold ${CLS[result.classification]}`}>{result.classification.toUpperCase()} — risk {(result.risk_score * 100).toFixed(0)}%</div>
                <div className="text-xs text-slate-400">{result.category} · model {(result.model_prob * 100).toFixed(0)}% · rules {(result.rule_score * 100).toFixed(0)}%</div>
                <ul className="mt-1 list-disc pl-4 text-xs text-slate-300">{result.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
              </div>
            )}
            <div className="border-t border-slate-700 pt-2">
              <div className="mb-1 text-xs text-slate-400">Demo traffic</div>
              <div className="flex flex-wrap gap-1">
                {['benign', 'dga_burst', 'tunnelling', 'phishing'].map((s) => (
                  <button key={s} className={btn} disabled={!!busy} onClick={() => run(s, () => post('/dns/simulate', { scenario: s }))}>{s.replace('_', ' ')}</button>
                ))}
              </div>
            </div>
          </div>
        </Card>

        <div className="lg:col-span-2"><Card title="Live DNS traffic">
          <div className="max-h-72 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-900 text-slate-400"><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Rcode</th><th>Verdict</th></tr></thead>
              <tbody>{queries.map((q) => (
                <tr key={q.id} className="border-t border-slate-800">
                  <td className="py-1 pr-2 text-slate-400">{time(q.timestamp)}</td><td className="pr-2">{q.client_ip}</td>
                  <td className="pr-2 font-mono">{q.domain}{q.blocked && ' 🚫'}</td><td>{q.query_type}</td><td>{q.response_code}</td>
                  <td className={CLS[q.classification]}>{q.classification} {(q.risk_score * 100).toFixed(0)}%</td>
                </tr>))}
                {!queries.length && <tr><td colSpan={6} className="py-4 text-center text-slate-500">No queries yet — use "Demo traffic" or point a device at the resolver.</td></tr>}
              </tbody>
            </table>
          </div>
        </Card></div>
      </div>

      <Card title="Alerts" right={<a className="text-xs text-sky-400 hover:underline" href="/api/v1/reports/alerts.csv">Export CSV</a>}>
        <div className="overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-400"><tr><th>Severity</th><th>Domain</th><th>Category</th><th>Risk</th><th>×</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>{alerts.map((a) => (<Fragment key={a.id}>
              <tr className="border-t border-slate-800 align-top">
                <td className="py-1"><span className={`rounded px-1.5 py-0.5 ${SEV[a.severity]}`}>{a.severity}</span></td>
                <td className="font-mono">{a.domain}{a.blocked && ' 🚫'}<div className="font-sans text-slate-500">{a.client_ip}</div></td>
                <td>{a.category}</td><td>{(a.risk_score * 100).toFixed(0)}%</td><td>{a.occurrences}</td>
                <td><select value={a.status} className="rounded bg-slate-800 p-0.5" disabled={!!busy}
                  onChange={(e) => run('s', () => api(`/alerts/${a.id}`, { method: 'PATCH', body: JSON.stringify({ status: e.target.value }) }))}>
                  {['new', 'investigating', 'confirmed', 'resolved', 'false_positive'].map((s) => <option key={s}>{s}</option>)}</select></td>
                <td className="space-x-1 whitespace-nowrap">
                  <button className={btn} disabled={!!busy || a.blocked} onClick={() => run('b', () => post('/domains/block', { domain: a.domain, reason: a.category }))}>Block</button>
                  <button className={btn} disabled={!!busy} onClick={() => run('a', () => post('/domains/allowlist', { domain: a.domain, reason: 'false positive' }))}>Allow</button>
                  <button className={btn} disabled={!!busy} onClick={() => run('x', async () => { await post(`/alerts/${a.id}/analyze`); setOpen(a.id); })}>Explain</button>
                  <button className={btn} onClick={() => setOpen(open === a.id ? null : a.id)}>Details</button>
                </td>
              </tr>
              {open === a.id && (<tr className="bg-slate-950/60"><td colSpan={7} className="p-2 text-slate-300">
                <ul className="list-disc pl-4">{a.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
                {a.analysis && <div className="mt-2 border-t border-slate-700 pt-2"><b>{a.analysis.summary}</b>
                  <ul className="list-disc pl-4">{a.analysis.recommendations.map((r, i) => <li key={i}>{r}</li>)}</ul>
                  <span className="text-slate-500">source: {a.analysis.provider}</span></div>}
              </td></tr>)}
            </Fragment>))}
            {!alerts.length && <tr><td colSpan={7} className="py-4 text-center text-slate-500">No alerts.</td></tr>}</tbody>
          </table>
        </div>
      </Card>

      <Card title="Blocked domains (sinkholed at the resolver)">
        <div className="flex flex-wrap gap-2">
          {blocked.map((b) => (
            <span key={b.domain} className="flex items-center gap-2 rounded bg-slate-800 px-2 py-1 font-mono text-xs">
              {b.domain}<button className="text-red-400" title="Unblock" onClick={() => run('u', () => post('/domains/unblock', { domain: b.domain }))}>✕</button>
            </span>))}
          {!blocked.length && <span className="text-xs text-slate-500">Nothing blocked.</span>}
        </div>
      </Card>
    </div>
  );
}
