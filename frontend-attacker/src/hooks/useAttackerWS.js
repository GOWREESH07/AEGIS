import { useState, useEffect, useRef, useCallback } from 'react';

export function useAttackerWS() {
  const [events, setEvents] = useState([]);
  const [wsStatus, setWsStatus] = useState('DISCONNECTED');
  const [runState, setRunState] = useState({
    runId: null,
    status: 'IDLE',
    currentStage: null,
    stages: {
      1: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      2: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      3: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      4: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      5: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      6: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      7: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      8: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
      9: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
    }
  });

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const backoffRef = useRef(1000);

  const connect = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const ws = new WebSocket('ws://localhost:8003/ws/events');
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus('CONNECTED');
      backoffRef.current = 1000;
    };

    ws.onclose = () => {
      setWsStatus('DISCONNECTED');
      wsRef.current = null;
      reconnectTimeoutRef.current = setTimeout(() => {
        backoffRef.current = Math.min(backoffRef.current * 2, 16000);
        connect();
      }, backoffRef.current);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Ensure timestamp exists for display
        const newEvent = { ...data, timestamp: data.timestamp || new Date().toISOString() };
        
        setEvents(prev => {
          const updated = [...prev, newEvent];
          if (updated.length > 500) return updated.slice(updated.length - 500);
          return updated;
        });

        // Update runState based on event
        setRunState(prev => {
          const next = { ...prev, stages: { ...prev.stages } };
          const stage = data.stage;
          const action = data.action; // jadepuffer.py uses `action`, not `type`

          // New run started
          if (data.run_id && data.run_id !== prev.runId) {
            next.runId = data.run_id;
            next.stages = {
              1: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              2: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              3: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              4: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              5: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              6: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              7: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              8: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
              9: { status: 'PENDING', elapsed_ms: 0, lastAction: '' },
            };
          }

          // Top-level run state transitions
          if (action === 'run_start') {
            next.status = 'RUNNING';
            if (data.run_id) next.runId = data.run_id;
          } else if (action === 'run_complete') {
            next.status = 'COMPLETED';
          } else if (action === 'run_stop' || action === 'run_stopped' || action === 'stopped') {
            next.status = 'STOPPED';
          } else if (action === 'connected') {
            // On reconnect, sync status from server detail if available
            const serverStatus = data.detail?.status;
            if (serverStatus === 'running') next.status = 'RUNNING';
            else if (serverStatus === 'idle') next.status = 'IDLE';
          }

          // Per-stage transitions
          if (stage && stage > 0 && next.stages[stage]) {
            next.currentStage = stage;
            const sData = { ...next.stages[stage] };

            if (action) sData.lastAction = action;
            if (data.detail?.elapsed_ms !== undefined && data.detail?.elapsed_ms !== null) {
              sData.elapsed_ms = data.detail.elapsed_ms;
            }

            if (action === 'stage_start') {
              sData.status = 'ACTIVE';
            } else if (action === 'stage_complete') {
              sData.status = data.blocked_by ? 'BLOCKED' : 'COMPLETE';
              if (data.detail?.elapsed_ms !== undefined && data.detail?.elapsed_ms !== null) {
                sData.elapsed_ms = data.detail.elapsed_ms;
              }
            } else if (action === 'blocked') {
              sData.status = 'BLOCKED';
              if (data.detail?.elapsed_ms !== undefined && data.detail?.elapsed_ms !== null) {
                sData.elapsed_ms = data.detail.elapsed_ms;
              }
            }
            next.stages[stage] = sData;
          }
          return next;
        });

      } catch (err) {
        console.error('Failed to parse WS message', err);
      }
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [connect]);

  return { events, runState, wsStatus };
}
