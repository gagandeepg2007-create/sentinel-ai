'use client';

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar, CartesianGrid } from 'recharts';
import { motion, useSpring, useTransform } from "framer-motion";

// Helper component for dynamic counting animations
function AnimatedNumber({ value }: { value: number }) {
  const spring = useSpring(value, { mass: 0.8, stiffness: 75, damping: 15 });
  const display = useTransform(spring, (current) => Math.round(current));
  useEffect(() => { spring.set(value); }, [value, spring]);
  return <motion.span>{display}</motion.span>;
}

interface KPIBlock {
  total_logs: number;
  critical_threats: number;
  anomalies_detected: number;
  clean_events: number;
  overall_risk_index: number;
}

interface MaliciousIP {
  ip: string;
  count: number;
}

interface TimelinePoint {
  timestamp: string;
  threats: number;
  total: number;
}

export default function AnalyticsDashboard() {
  const [isMounted, setIsMounted] = useState(false);
  const [kpis, setKpis] = useState<KPIBlock | null>(null);
  const [topIps, setTopIps] = useState<MaliciousIP[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [isIsolating, setIsIsolating] = useState(false);
  const [webhookAlert, setWebhookAlert] = useState<{ip: string, message: string} | null>(null);

  useEffect(() => {
    setIsMounted(true);
    const fetchDashboardAnalytics = async () => {
      try {
        const token = localStorage.getItem('accessToken') || localStorage.getItem('access_token') || localStorage.getItem('token') || '';
        const response = await axios.get('http://127.0.0.1:8000/api/security/dashboard-stats/', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.data.status === 'success') {
          setKpis(response.data.kpis);
          setTopIps(response.data.top_malicious_ips);
          setTimeline(response.data.threat_timeline);
        }
      } catch (error) { console.error("Telemetry update failed", error); }
      finally { setLoading(false); }
    };
    fetchDashboardAnalytics();
    const liveUpdateInterval = setInterval(fetchDashboardAnalytics, 2000);
    return () => clearInterval(liveUpdateInterval);
  }, []);

  const executeContainment = async (targetIp: string) => {
    if (isIsolating) return;
    setIsIsolating(true);
    try {
      const token = localStorage.getItem('accessToken') || localStorage.getItem('access_token') || localStorage.getItem('token') || '';
      await axios.post('http://127.0.0.1:8000/api/security/containment/', { source_ip: targetIp, threat_score: 100, threat_type: "CRITICAL_ML_ANOMALY" }, { headers: { 'Authorization': `Bearer ${token}` } });
      setWebhookAlert({ ip: targetIp, message: "WEBHOOK DISPATCHED: Firewall containment rule applied globally & SOC alerted via Slack." });
      setTimeout(() => setWebhookAlert(null), 6000);
    } catch (error) { console.error("Containment failed:", error); }
    finally { setIsIsolating(false); }
  };

  if (!isMounted) return null;
  if (loading && !kpis) return <div className="min-h-screen bg-neutral-950 flex items-center justify-center text-neutral-400 font-mono text-sm animate-pulse">&gt; INITIALIZING TELEMETRY ANALYTICS MESH...</div>;

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 p-6 font-sans">
      {webhookAlert && (
        <div className="mb-6 p-4 bg-red-950/80 border border-red-500 rounded-xl flex items-center justify-between shadow-[0_0_20px_rgba(239,68,68,0.3)] animate-pulse">
          <div className="flex items-center gap-4">
            <span className="text-3xl">🚨</span>
            <div>
              <div className="text-red-400 font-bold font-mono text-sm tracking-widest">ACTIVE DEFENSE MITIGATION TRIGGERED</div>
              <div className="text-red-200 font-mono text-xs mt-1">{webhookAlert.message} <span className="font-bold text-white">TARGET: {webhookAlert.ip}</span></div>
            </div>
          </div>
        </div>
      )}

      <header className="mb-8 border-b border-neutral-900 pb-4">
        <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-3">
          <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
          VIGIL-X // OPERATIONAL SECURITY HUB
        </h1>
        <p className="text-xs text-neutral-500 mt-2 font-mono">Real-time non-relational telemetry aggregation cluster matrices.</p>
      </header>

      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        {[ { label: "Total Telemetry Logs", val: kpis?.total_logs, color: "text-neutral-100" },
           { label: "🚨 Critical Threats", val: kpis?.critical_threats, color: "text-red-400" },
           { label: "⚠️ ML Anomalies", val: kpis?.anomalies_detected, color: "text-amber-400" },
           { label: "✅ Benign Events", val: kpis?.clean_events, color: "text-emerald-400" },
           { label: "Overall Risk Index", val: kpis?.overall_risk_index, color: (kpis?.overall_risk_index ?? 0) > 40 ? "text-red-500" : "text-emerald-500" }
        ].map((item, i) => (
          <div key={i} className="bg-neutral-900/50 border border-neutral-800 p-5 rounded-xl transition-all hover:bg-neutral-900">
            <div className="text-[10px] font-mono text-neutral-500 uppercase tracking-wider">{item.label}</div>
            <div className={`text-3xl font-bold font-mono mt-3 ${item.color}`}>
              <AnimatedNumber value={item.val || 0} />{item.label === "Overall Risk Index" ? "%" : ""}
            </div>
          </div>
        ))}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-neutral-900/50 border border-neutral-800 p-6 rounded-2xl flex flex-col h-[350px]">
          <h3 className="text-[11px] font-mono font-bold mb-6 text-neutral-400 uppercase tracking-widest flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4 text-emerald-500"><path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z" /></svg>
            Threat Incidence Vector Trends
          </h3>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" vertical={false} />
              <XAxis dataKey="timestamp" stroke="#525252" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis stroke="#525252" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#262626', color: '#f5f5f5', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }} />
              <Area type="monotone" dataKey="total" stroke="#525252" fill="#333" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="#7f1d1d" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-neutral-900/50 border border-neutral-800 p-6 rounded-2xl flex flex-col h-[350px]">
          <h3 className="text-[11px] font-mono font-bold mb-6 text-neutral-400 uppercase tracking-widest flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4 text-amber-500"><path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" /></svg>
            Repeated Adversarial Origins
          </h3>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={topIps} layout="vertical" margin={{ top: 0, right: 0, left: 30, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" horizontal={false} />
              <XAxis type="number" stroke="#525252" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis dataKey="ip" type="category" stroke="#a3a3a3" fontSize={11} fontFamily="monospace" tickLine={false} axisLine={false} />
              <Tooltip cursor={{ fill: '#171717' }} contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#262626', color: '#f5f5f5', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }} />
              <Bar dataKey="count" fill="#d97706" radius={[0, 4, 4, 0]} barSize={20} />
            </BarChart>
          </ResponsiveContainer>
          {topIps.length > 0 && (
            <button onClick={() => executeContainment(topIps[0].ip)} disabled={isIsolating} className="mt-4 w-full py-3 bg-red-950/40 hover:bg-red-900/80 border border-red-900/50 text-red-400 text-[10px] font-mono font-bold tracking-widest rounded-lg transition-all cursor-pointer disabled:opacity-50">
              {isIsolating ? 'EXECUTING MITIGATION PAYLOAD...' : `[ INITIATE AUTO-CONTAINMENT ON ${topIps[0].ip} ]`}
            </button>
          )}
        </div>
      </section>
    </main>
  );
}