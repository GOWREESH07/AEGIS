import { useState, useEffect, useCallback } from 'react';

const API_BASE = typeof window !== 'undefined'
  ? `http://${window.location.hostname || 'localhost'}:8000/api/aegis`
  : 'http://localhost:8000/api/aegis';



export function useAegisAPI() {
  const [status, setStatus] = useState({ enabled: true, blocklist_count: 0, signatures_stored: 0 });
  const [blocklist, setBlocklist] = useState([]);
  const [healingStats, setHealingStats] = useState({ delta_ms: 0, improved: true });
  const [metricsData, setMetricsData] = useState([]);
  const [escalations, setEscalations] = useState([]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      if (res.ok) setStatus(await res.json());
    } catch (e) { console.error(e) }
  }, []);

  const fetchBlocklist = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/blocklist`);
      if (res.ok) setBlocklist(await res.json());
    } catch (e) { console.error(e) }
  }, []);

  const fetchEscalations = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/escalations`);
      if (res.ok) setEscalations(await res.json());
    } catch (e) { console.error(e) }
  }, []);

  const resolveEscalation = async (escalationId, decision) => {
    try {
      await fetch(`${API_BASE}/escalations/${escalationId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      fetchEscalations();
      fetchBlocklist();
    } catch (e) { console.error(e) }
  };

  const fetchHealingStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/healing-stats`);
      if (res.ok) setHealingStats(await res.json());
    } catch (e) { console.error(e) }
  }, []);

  const fetchMetrics = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/metrics`);
      if (res.ok) setMetricsData(await res.json());
    } catch (e) { console.error(e) }
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchBlocklist();
    fetchEscalations();
    fetchHealingStats();
    fetchMetrics();

    const interval5s = setInterval(() => {
      fetchStatus();
      fetchBlocklist();
      fetchEscalations();
    }, 5000);

    const interval10s = setInterval(() => {
      fetchHealingStats();
      fetchMetrics();
    }, 10000);

    return () => {
      clearInterval(interval5s);
      clearInterval(interval10s);
    };
  }, [fetchStatus, fetchBlocklist, fetchEscalations, fetchHealingStats, fetchMetrics]);

  const toggleAegis = async () => {
    try {
      // Send the toggled state based on current status
      const newState = !status.enabled;
      await fetch(`${API_BASE}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState }),
      });
      fetchStatus();
    } catch (e) { console.error(e) }
  };

  const resetAegis = async () => {
    try {
      await fetch(`${API_BASE}/reset`, { method: 'POST' });
      fetchStatus();
      fetchBlocklist();
    } catch (e) { console.error(e) }
  };

  return { status, blocklist, escalations, resolveEscalation, healingStats, metricsData, toggleAegis, resetAegis };
}
