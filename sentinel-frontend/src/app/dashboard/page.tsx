'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import axios from 'axios';

// Define explicit structural layout types for our live log streams
interface SecurityLog {
  id: string;
  timestamp: string;
  sourceIp: string;
  eventType: 'BRUTE_FORCE' | 'SQL_INJECTION' | 'MALWARE_BEACON' | 'PORT_SCAN';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  status: 'BLOCKED' | 'ISOLATED' | 'MONITORING';
}

export default function DashboardPage() {
  const router = useRouter();
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [threatLevel, setThreatLevel] = useState('ELEVATED');
  const [isShieldActive, setIsShieldActive] = useState(true);
  const [authorized, setAuthorized] = useState(false);

  // FEATURE 1: Secure Session Terminator (Logout)
  const handleLogout = () => {
    // Purge tokens from client-side storage vaults
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    
    // Revoke layout compiling permissions and push operator to root gate
    setAuthorized(false);
    router.push('/');
  };

  // FEATURE 2: Real Backend Data Sync Fetcher
  const fetchLiveLogs = async () => {
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) return;

      // Request current anomalies directly from Django API Endpoint
      const response = await axios.get('http://127.0.0.1:8000/api/security/logs/', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      // Expected backend structure: Array of items conforming to SecurityLog interface
      if (Array.isArray(response.data)) {
        setLogs(response.data.slice(0, 10)); // Keep top 10 rows
      }
    } catch (err: any) {
      console.error('Telemetry stream fetching error:', err);
      
      // If backend throws an absolute Auth Token Expiry (401), kick user back to gateway
      if (err.response?.status === 401) {
        handleLogout();
      }
    }
  };

  // Core Session Guard & Live Stream Process Hook
  useEffect(() => {
    // 1. Check browser local storage for a valid auth token
    const token = localStorage.getItem('accessToken');
    if (!token) {
      router.push('/');
      return;
    }
    
    // Token exists, drop the shield overlay
    setAuthorized(true);

    // 2. Execute initial fetch of live data immediately on mount
    fetchLiveLogs();

    // 3. Polling Mechanism: Synchronize with backend telemetry every 5 seconds
    const interval = setInterval(() => {
      fetchLiveLogs();
    }, 5000);

    return () => clearInterval(interval);
  }, [router]);

  // Dynamic threat level index calculator based on the telemetry dataset profile
  useEffect(() => {
    if (logs.some(log => log.severity === 'CRITICAL')) {
      setThreatLevel('CRITICAL');
    } else if (logs.some(log => log.severity === 'HIGH')) {
      setThreatLevel('HIGH');
    } else if (logs.length > 0) {
      setThreatLevel('ELEVATED');
    } else {
      setThreatLevel('NOMINAL');
    }
  }, [logs]);

  // If the hook has not authorized the operator yet, render a blank dark slate to prevent UI flashing
  if (!authorized) {
    return (
      <div className="min-h-screen bg-neutral-950 text-neutral-500 font-mono flex items-center justify-center text-xs tracking-widest">
        AUTHENTICATING_SECURE_SESSION...
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 font-sans p-6 selection:bg-emerald-500 selection:text-black">
      {/* Top Application Management Navigation Grid Navbar */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-neutral-800 pb-5 mb-8 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
            Sentinel_AI Console
          </h1>
          <p className="text-xs font-mono text-neutral-400 mt-1">SIEM Threat Intelligence Node // Root Operator</p>
        </div>

        {/* Action Controls: Log Ingestion Router, Mitigation Switch, & Security Logout */}
        <div className="flex flex-wrap items-center gap-4">
          <Link 
            href="/dashboard/logs" 
            className="px-4 py-3 bg-emerald-600 hover:bg-emerald-500 text-neutral-950 text-xs font-mono font-bold tracking-wider rounded-xl transition-all shadow-md shadow-emerald-950/20 uppercase"
          >
            + Ingest New Syslogs
          </Link>

          <div className="flex items-center gap-4 bg-neutral-900 border border-neutral-800 rounded-xl p-3">
            <div className="text-right">
              <div className="text-xs font-mono text-neutral-400">IPS PROACTIVE MITIGATION</div>
              <div className={`text-xs font-bold ${isShieldActive ? 'text-emerald-400' : 'text-red-400'}`}>
                {isShieldActive ? 'ACTIVE_ARMED' : 'SYSTEM_DISABLED'}
              </div>
            </div>
            <button 
              onClick={() => setIsShieldActive(!isShieldActive)}
              className={`w-12 h-6 flex items-center rounded-full p-1 cursor-pointer transition-colors duration-300 ${isShieldActive ? 'bg-emerald-600' : 'bg-neutral-700'}`}
            >
              <div className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-300 ${isShieldActive ? 'translate-x-6' : 'translate-x-0'}`}></div>
            </button>
          </div>

          <button
            onClick={handleLogout}
            className="px-4 py-3 bg-neutral-900 hover:bg-red-950/40 border border-neutral-800 hover:border-red-900/50 rounded-xl text-xs font-mono tracking-wider font-bold text-neutral-400 hover:text-red-400 transition-all cursor-pointer"
          >
            TERMINATE_SESSION ↗
          </button>
        </div>
      </header>

      {/* Main Grid Metrics Panel Layout Dashboard Matrix */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <div className="text-xs font-mono text-neutral-400 uppercase tracking-wider">Infrastructure Status</div>
          <div className="text-3xl font-bold text-white mt-2 font-mono">99.98%</div>
          <div className="text-xs text-neutral-500 mt-1">All secure collection nodes reporting clear</div>
        </div>

        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <div className="text-xs font-mono text-neutral-400 uppercase tracking-wider">Threat Level Index</div>
          <div className={`text-3xl font-bold mt-2 font-mono ${threatLevel === 'CRITICAL' ? 'text-red-500 animate-pulse' : 'text-amber-500'}`}>
            {threatLevel}
          </div>
          <div className="text-xs text-neutral-500 mt-1">Internal telemetry pattern anomaly tracking</div>
        </div>

        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <div className="text-xs font-mono text-neutral-400 uppercase tracking-wider">Monitored Bandwidth</div>
          <div className="text-3xl font-bold text-emerald-400 mt-2 font-mono">{logs.length > 0 ? '4,128 pps' : '0 pps'}</div>
          <div className="text-xs text-neutral-500 mt-1">Real-time edge packet filtering metrics</div>
        </div>
      </section>

      {/* Live Operational Incident Log Tracking Streams Terminal Container Box */}
      <section className="bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl overflow-hidden">
        <div className="bg-neutral-900 border-b border-neutral-800 px-6 py-4 flex justify-between items-center">
          <h2 className="text-sm font-semibold tracking-wider font-mono text-white uppercase">Live Security Event Log Stream</h2>
          <span className="px-2 py-0.5 rounded bg-neutral-800 border border-neutral-700 text-neutral-400 text-[10px] font-mono animate-pulse">
            REALTIME_FEED
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-800 text-neutral-400 font-mono text-xs uppercase bg-neutral-950/50">
                <th className="px-6 py-3.5 font-medium">Timestamp</th>
                <th className="px-6 py-3.5 font-medium">Source Attacker IP</th>
                <th className="px-6 py-3.5 font-medium">Vector Trigger Anomaly</th>
                <th className="px-6 py-3.5 font-medium">Severity</th>
                <th className="px-6 py-3.5 font-medium text-right">IPS Defense Response</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/50 font-mono text-xs">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-neutral-500 tracking-widest uppercase">
                    No active threat vectors parsed from backend telemetry.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-neutral-800/30 transition-colors">
                    <td className="px-6 py-4 text-neutral-400 whitespace-nowrap">{log.timestamp}</td>
                    <td className="px-6 py-4 text-white font-medium whitespace-nowrap tracking-wide">{log.sourceIp}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="px-2 py-1 rounded bg-neutral-950 border border-neutral-800 text-neutral-300 text-[11px]">
                        {log.eventType}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider ${
                        log.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800/40' :
                        log.severity === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800/40' :
                        'bg-blue-950 text-blue-400 border border-blue-800/40'
                      }`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right whitespace-nowrap">
                      <span className={`font-semibold ${
                        log.status === 'BLOCKED' ? 'text-emerald-400' :
                        log.status === 'ISOLATED' ? 'text-amber-400' : 'text-neutral-400'
                      }`}>
                        🗲 {log.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}