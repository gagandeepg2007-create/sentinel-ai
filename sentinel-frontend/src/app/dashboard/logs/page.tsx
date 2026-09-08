'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import axios from 'axios';

interface ThreatIntelLookup {
  matched: boolean;
  actor?: string;
  threat_type?: string;
  confidence_score?: number;
  is_anomaly?: boolean;
  threat_verdict?: string; 
}

interface LogRecord {
  timestamp: string;
  severity: string;
  source_ip: string;
  target_port: number;
  http_method: string;
  http_status: number;
  message: string;
  parsed_successfully: boolean;
  anomaly_score: number;
  threat_intel_lookup?: ThreatIntelLookup;
}

export default function LogIngestionPage() {
  const router = useRouter();
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<'IDLE' | 'UPLOADING' | 'SUCCESS' | 'ERROR'>('IDLE');
  const [errorMessage, setErrorMessage] = useState('');
  const [registryToken, setRegistryToken] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [ingestedRecords, setIngestedRecords] = useState<LogRecord[]>([]);

  useEffect(() => {
    const token = 
      localStorage.getItem('accessToken') || 
      localStorage.getItem('access_token') || 
      localStorage.getItem('token');
    
    if (!token) {
      setAuthorized(false);
      router.push('/');
    } else {
      setAuthorized(true);
    }
  }, [router]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragActive(true);
    } else if (e.type === "dragleave") {
      setIsDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await processLogFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      await processLogFile(e.target.files[0]);
    }
  };

  const processLogFile = async (file: File) => {
    if (!file.name.endsWith('.log') && !file.name.endsWith('.txt')) {
      setUploadStatus('ERROR');
      setErrorMessage('Invalid file system format. Please supply a structured ASCII .log or .txt sequence.');
      return;
    }

    setUploadStatus('UPLOADING');
    setErrorMessage('');
    setIngestedRecords([]);
    
    const formData = new FormData();
    formData.append('file', file);

    const token = 
      localStorage.getItem('accessToken') || 
      localStorage.getItem('access_token') || 
      localStorage.getItem('token');

    if (!token) {
      setUploadStatus('ERROR');
      setErrorMessage('Session trace dropped. Local authentication token is absent.');
      return;
    }

    try {
      const response = await axios.post('http://127.0.0.1:8000/api/security/logs/', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 201 || response.status === 200) {
        setUploadStatus('SUCCESS');
        const finalUuid = response.data.ingestion_uuid || response.data.ingestion_id || response.data.id || 'SUCCESS_MOCK_UUID';
        setRegistryToken(finalUuid);
        
        if (response.data && Array.isArray(response.data.records)) {
          setIngestedRecords(response.data.records);
        } else {
          setIngestedRecords([]);
        }

        setTimeout(async () => {
          try {
            const syncResponse = await axios.get(`http://127.0.0.1:8000/api/security/logs/?uuid=${finalUuid}`, {
              headers: { 
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
              }
            });
            
            if (syncResponse.data && Array.isArray(syncResponse.data.records)) {
              setIngestedRecords(syncResponse.data.records);
            }
          } catch (syncErr: any) {
            // Handled silently to keep production console clean
          }
        }, 1500);
      }
    } catch (err: any) {
      setUploadStatus('ERROR');
      if (err.response?.status === 401) {
        setErrorMessage('Identity session token expired or compromised. Re-authentication mandatory.');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('access_token');
        localStorage.removeItem('token');
        setAuthorized(false);
        router.push('/');
      } else if (err.response?.status === 404) {
        setErrorMessage('Ingestion pipeline routing endpoint mismatch (404). Check backend URLs or trailing slashes.');
      } else {
        setErrorMessage(err.response?.data?.error || 'Pipeline submission error. Verify server state metrics.');
      }
    }
  };

  if (!authorized) {
    return (
      <div className="min-h-screen bg-neutral-950 text-neutral-500 font-mono flex items-center justify-center text-xs tracking-widest">
        INITIALIZING_TELEMETRY_ROUTE_GUARD...
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 font-sans p-6 selection:bg-emerald-500 selection:text-black">
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-neutral-800 pb-5 mb-8 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
            Sentinel_AI // Raw Telemetry Pipeline
          </h1>
          <p className="text-xs font-mono text-neutral-400 mt-1">SIEM Distributed Log Staging Cluster Enclave // Layer 2 Sandbox Broker</p>
        </div>
        <Link 
          href="/dashboard" 
          className="px-4 py-2.5 bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 text-neutral-400 hover:text-white text-xs font-mono tracking-wider rounded-xl transition-all uppercase"
        >
          &larr; Return to Operations Matrix
        </Link>
      </header>

      <section className="bg-amber-950/20 border border-amber-900/30 rounded-xl p-5 mb-8 max-w-5xl">
        <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono">Hybrid Database Ingestion Topography:</h3>
        <p className="text-xs text-neutral-400 mt-1.5 leading-relaxed">
          By dropping network logs here, payloads intentionally bypass the structured, ACID-compliant relational SQL node. Files split into streaming string rows mapping natively to polymorphic JSON collections inside the <strong className="text-neutral-200">MongoDB Data Plane</strong>, protecting active relational table indexes from traffic throughput lockups.
        </p>
      </section>

      <section className="max-w-5xl">
        <div 
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          className={`relative border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 flex flex-col items-center justify-center min-h-[260px] ${
            isDragActive 
              ? 'border-emerald-500 bg-emerald-950/10 shadow-xl shadow-emerald-950/5' 
              : 'border-neutral-800 bg-neutral-900/40 hover:bg-neutral-900/60 hover:border-neutral-700'
          }`}
        >
          <input 
            type="file" 
            id="log-file-input"
            className="hidden" 
            accept=".log,.txt"
            onChange={handleFileInput}
          />
          
          <label htmlFor="log-file-input" className="cursor-pointer flex flex-col items-center group">
            <div className={`w-14 h-14 rounded-full flex items-center justify-center mb-4 border transition-colors ${
              isDragActive ? 'bg-emerald-500/20 border-emerald-400 text-emerald-400' : 'bg-neutral-950 border-neutral-800 text-neutral-400 group-hover:border-neutral-600 group-hover:text-neutral-200'
            }`}>
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v6m3-3H9m12 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
              </svg>
            </div>
            <p className="text-sm font-medium text-neutral-200 tracking-wide font-sans">
              {isDragActive ? 'Drop syslog container asset now...' : 'Drag & drop system syslogs here, or click to browse'}
            </p>
            <p className="text-xs text-neutral-500 mt-2 font-mono">Supported formats: Standard ASCII .log or plain text .txt up to 5MB</p>
          </label>
        </div>

        {uploadStatus !== 'IDLE' && (
          <div className="mt-6 border border-neutral-800 rounded-xl overflow-hidden shadow-xl animate-fadeIn">
            <div className="bg-neutral-950 border-b border-neutral-800 px-4 py-2.5 flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${
                uploadStatus === 'UPLOADING' ? 'bg-amber-500 animate-pulse' :
                uploadStatus === 'SUCCESS' ? 'bg-emerald-500' : 'bg-red-500'
              }`} />
              <span className="text-[10px] font-mono font-bold tracking-wider text-neutral-400 uppercase">
                Pipeline_Feedback_Signal // [{uploadStatus}]
              </span>
            </div>

            <div className="bg-neutral-900/90 p-5 font-mono text-xs leading-relaxed">
              {uploadStatus === 'UPLOADING' && (
                <div className="text-amber-400 animate-pulse tracking-wide">
                  &gt;&gt; STREAMING_BINARY_BUFFER_ARRAY_TO_DJANGO_BACKEND... HOLD OPERATOR CONTEXT
                </div>
              )}

              {uploadStatus === 'ERROR' && (
                <div className="text-red-400 tracking-wide">
                  <span className="font-bold text-red-500">Ingestion Rejected:</span> {errorMessage}
                </div>
              )}

              {uploadStatus === 'SUCCESS' && (
                <div className="text-emerald-400 space-y-4">
                  <div className="font-bold">&gt;&gt; LOG_INGESTION_SUCCESS: PIPELINE_MUTATION_COMPLETE</div>
                  <div className="text-neutral-400 text-[11px]">
                    Raw unparsed rows split, converted to BSON layout, and cleanly pushed natively into the <span className="text-emerald-500">raw_syslogs</span> schema collection. Relational metrics bypass initialized successfully.
                  </div>
                  
                  <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800 mt-2 text-white flex flex-col gap-1 select-all cursor-pointer">
                    <span className="text-[10px] text-neutral-500 block">System Monitored UUIDv4 Registry Token:</span>
                    <span className="text-emerald-400 tracking-wider text-xs font-bold">{registryToken}</span>
                  </div>

                  {ingestedRecords.length > 0 && (
                    <div className="mt-6 pt-4 border-t border-neutral-800/80">
                      <div className="text-[11px] uppercase tracking-wider font-bold text-neutral-300 mb-3 flex items-center gap-1.5">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-3.5 h-3.5 text-emerald-400">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0V12a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 12V5.25" />
                        </svg>
                        Inline_AI_Inference_Stream_Inspection_Output:
                      </div>
                      
                      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                        {ingestedRecords.map((record, index) => {
                          const verdict = record.threat_intel_lookup?.threat_verdict || '';
                          const displayScore = record.anomaly_score ?? 0;
                          
                          const isThreatIntel = 
                            verdict.startsWith("CRITICAL") || 
                            verdict.includes("MATCH") || 
                            record.severity === 'CRITICAL' ||
                            displayScore >= 90;
                            
                          const isMlAnomaly = 
                            verdict.includes("SUSPICIOUS") || 
                            verdict.includes("ANOMALY") || 
                            record.threat_intel_lookup?.is_anomaly === true ||
                            (!isThreatIntel && displayScore >= 50);
                          
                          return (
                            <div 
                              key={index} 
                              className={`p-3 rounded-lg border text-[11px] transition-all flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 ${
                                isThreatIntel ? 'bg-red-950/30 border-red-900/50 text-red-200 shadow-lg shadow-red-950/10' :
                                isMlAnomaly ? 'bg-amber-950/20 border-amber-900/40 text-amber-200' :
                                'bg-neutral-950/60 border-neutral-800/60 text-neutral-300'
                              }`}
                            >
                              <div className="space-y-1 flex-1 min-w-0 w-full">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="text-neutral-500 text-[10px]">{record.timestamp}</span>
                                  <span className={`font-bold px-1.5 py-0.2 rounded text-[9px] ${
                                    isThreatIntel ? 'bg-red-900/60 text-red-100' :
                                    isMlAnomaly ? 'bg-amber-900/50 text-amber-200' : 'bg-neutral-800 text-neutral-400'
                                  }`}>{isThreatIntel ? 'CRITICAL' : record.severity}</span>
                                  <span className="font-mono text-neutral-400">Src_IP: <strong className="text-neutral-200">{record.source_ip}</strong></span>
                                  <span className="text-neutral-500">Port: {record.target_port}</span>
                                </div>
                                <div className="text-neutral-400 truncate font-mono text-[10px] bg-neutral-950/40 p-1 rounded border border-neutral-900">
                                  {record.message.length > 85 ? `${record.message.substring(0, 85)}...` : record.message}
                                </div>
                              </div>

                              <div className="flex flex-col items-end gap-1 shrink-0 self-stretch sm:self-auto justify-center border-t sm:border-t-0 border-neutral-800/50 pt-2 sm:pt-0">
                                {isThreatIntel ? (
                                  <div className="text-right">
                                    <span className="inline-flex items-center px-2.5 py-0.5 rounded bg-red-900/50 text-red-200 font-bold border border-red-600 animate-pulse text-[10px]">
                                      🚨 CRITICAL_THREAT ({displayScore}%)
                                    </span>
                                  </div>
                                ) : isMlAnomaly ? (
                                  <div className="text-right">
                                    <span className="inline-flex items-center px-2 py-0.5 rounded bg-amber-900/40 text-amber-300 font-medium border border-amber-700 text-[10px]">
                                      ⚠️ ML_ANOMALY ({displayScore}%)
                                    </span>
                                  </div>
                                ) : (
                                  <div className="text-right">
                                    <span className="inline-flex items-center px-2 py-0.5 rounded bg-neutral-900 text-neutral-400 text-[10px] border border-neutral-800">
                                      ✅ BENIGN ({displayScore}%)
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </section>
    </main>
  );
}