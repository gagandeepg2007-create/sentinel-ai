'use client';

import React, { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // 1. Fire authentication request to your Django REST backend
      const response = await axios.post('http://127.0.0.1:8000/api/auth/login/', {
        email,
        password,
      });

      // 2. If backend validates credentials and issues the JWT token
      if (response.data.access) {
        localStorage.setItem('accessToken', response.data.access);
        localStorage.setItem('refreshToken', response.data.refresh);
        setSuccess(true);

        // 3. THE BRIDGE: Wait 1 second for the success message to show, then auto-route to dashboard
        setTimeout(() => {
          router.push('/dashboard');
        }, 1000);
      }
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Authentication failed. Access Denied.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center bg-neutral-950 text-neutral-100 font-sans p-4">
      {/* Structural Background Cyber Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f1f1f_1px,transparent_1px),linear-gradient(to_bottom,#1f1f1f_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-20 pointer-events-none"></div>

      <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-xl p-8 shadow-2xl relative z-10 backdrop-blur-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 text-xs font-mono tracking-wider mb-3">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            SENTINEL_AI SYSTEM GATEWAY
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Operator Sign-In</h1>
          <p className="text-sm text-neutral-400 mt-1">Authorized security personnel only</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-950/30 border border-red-500/30 rounded-lg text-sm text-red-400 font-mono">
            ⚠️ {error}
          </div>
        )}

        {success && (
          <div className="mb-6 p-4 bg-emerald-950/30 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 font-mono">
            🛡️ Identity verified. Access granted. Redirecting...
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-5">
          <div>
            <label className="block text-xs font-mono tracking-wider text-neutral-400 uppercase mb-2">Corporate Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-500 transition-colors placeholder-neutral-600"
              placeholder="operator@sentinel.ai"
            />
          </div>

          <div>
            <label className="block text-xs font-mono tracking-wider text-neutral-400 uppercase mb-2">Security Blueprint Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-500 transition-colors placeholder-neutral-600"
              placeholder="••••••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading || success}
            className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-neutral-800 disabled:text-neutral-500 text-white font-medium rounded-lg text-sm py-3 transition-colors shadow-lg shadow-emerald-900/20 mt-2 cursor-pointer"
          >
            {loading ? 'Decrypting Credentials...' : 'Initialize Secure Session'}
          </button>
        </form>
      </div>
    </main>
  );
}