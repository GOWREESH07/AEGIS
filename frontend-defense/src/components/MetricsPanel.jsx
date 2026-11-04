import React from 'react';
import {
  LineChart, Line, XAxis, YAxis,
  ResponsiveContainer, Tooltip, ReferenceLine,
} from 'recharts';

const STAGE_NAMES = { 1: 'RECON', 2: 'ADAPT', 3: 'AILM', 4: 'LATERAL', 5: 'EXEC' };

const MonoTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#111', border: '1px solid #2a2a2a',
      padding: '6px 10px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11,
    }}>
      <div style={{ color: '#888' }}>{STAGE_NAMES[label] || `S${label}`}</div>
      <div style={{ color: '#f5a623' }}>{payload[0].value.toFixed(1)} ms</div>
    </div>
  );
};

export function MetricsPanel({ stageMetrics, latencyHistory, attackSuccessRate, healingStats, metricsData }) {
  // stageMetrics: [{ stage, latency, detectRate, fpRate }] — computed live from WS
  // latencyHistory: [{ stage, latency }] — time-to-block per stage
  // attackSuccessRate: number 0–100
  // healingStats: from /api/aegis/healing-stats — { avg_delta_ms, signatures_stored, … }
  // metricsData: from /api/aegis/metrics — { stages: [...], attack_success_rate, self_healing_delta_ms }

  const metrics = [1, 2, 3, 4, 5].map(s => {
    const live = stageMetrics?.find(m => m.stage === s);
    const benchmark = metricsData?.stages?.find(entry => entry.stage === s);
    
    // If live has active data (attack in progress or completed), prioritize live
    if (live && (live.latency > 0 || live.detectRate > 0)) {
      return {
        stage: s,
        latency: live.latency,
        detectRate: live.detectRate,
        fpRate: benchmark ? benchmark.fp_rate : 0.8,
      };
    }

    if (benchmark) {
      return {
        stage: s,
        latency: benchmark.mean_ms,
        detectRate: benchmark.detect_rate,
        fpRate: benchmark.fp_rate,
      };
    }

    return {
      stage: s,
      latency: 0,
      detectRate: 0,
      fpRate: 0,
    };
  });

  const chartData = latencyHistory?.length ? latencyHistory : metrics.map(m => ({
    stage: m.stage, latency: m.latency,
  }));

  const sigCount   = healingStats?.signatures_stored ?? 0;
  const healDelta  = (healingStats?.avg_delta_ms && healingStats.avg_delta_ms !== 0)
    ? healingStats.avg_delta_ms
    : (metricsData?.self_healing_delta_ms ?? -5.9);

  const successRate = attackSuccessRate !== undefined
    ? attackSuccessRate
    : (metricsData?.attack_success_rate ?? 0);

  const validLatencies = chartData.map(d => d.latency).filter(l => typeof l === 'number' && !isNaN(l) && l > 0);
  const maxVal = validLatencies.length > 0 ? Math.max(...validLatencies) : 50;
  const yMax = Math.max(50, Math.ceil((maxVal * 1.25) / 10) * 10);

  return (
    <div style={{ display: 'flex', height: '100%' }}>

      {/* ── LEFT: Latency Sparkline ─────────────────────────────── */}
      <div style={{
        flex: 1, padding: '14px 16px', display: 'flex', flexDirection: 'column',
        borderRight: '1px solid #2a2a2a',
      }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.08em', marginBottom: 12 }}>
          LATENCY PROFILE (MS)
        </div>
        <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData} margin={{ top: 4, right: 8, left: -24, bottom: 4 }}>
              <XAxis
                dataKey="stage"
                tickFormatter={v => STAGE_NAMES[v] || `S${v}`}
                tick={{ fill: '#555', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}
                axisLine={false} tickLine={false}
              />
              <YAxis
                domain={[0, yMax]}
                tickCount={4}
                allowDecimals={false}
                tick={{ fill: '#555', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}
                axisLine={false} tickLine={false}
                tickFormatter={v => `${v}`}
              />

              <Tooltip content={<MonoTooltip />} />
              <ReferenceLine y={0} stroke="#2a2a2a" />
              <Line
                type="monotone"
                dataKey="latency"
                stroke="#f5a623"
                strokeWidth={1.5}
                dot={{ r: 3, fill: '#f5a623', strokeWidth: 0 }}
                activeDot={{ r: 4, fill: '#fff' }}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
        {/* bottom: summary stats below chart */}
        <div style={{
          display: 'flex', gap: 16, marginTop: 8,
          paddingTop: 8, borderTop: '1px solid #1a1a1a',
        }}>
          <div>
            <div style={{ fontSize: 9, color: '#444', marginBottom: 2 }}>SIGS STORED</div>
            <div className="mono" style={{ fontSize: 13, color: '#f5a623' }}>{sigCount}</div>
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#444', marginBottom: 2 }}>AVG FIRST</div>
            <div className="mono" style={{ fontSize: 13, color: '#c9c9c9' }}>
              {(healingStats?.avg_first_ms ?? 0).toFixed(0)}ms
            </div>
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#444', marginBottom: 2 }}>AVG SECOND</div>
            <div className="mono" style={{ fontSize: 13, color: '#c9c9c9' }}>
              {(healingStats?.avg_second_ms ?? 0).toFixed(0)}ms
            </div>
          </div>
        </div>
      </div>

      {/* ── RIGHT: Aggregate Table + Stats ──────────────────────── */}
      <div style={{ flex: 1, padding: '14px 16px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.08em', marginBottom: 12 }}>
          AGGREGATE PERFORMANCE
        </div>

        <table style={{ width: '100%', borderCollapse: 'collapse', flex: 1 }}>
          <thead>
            <tr>
              {['STAGE', 'MEAN MS', 'DETECT %', 'FP %'].map(h => (
                <th key={h} style={{
                  textAlign: 'left', padding: '4px 6px',
                  borderBottom: '1px solid #2a2a2a',
                  fontSize: 10, color: '#555',
                  fontFamily: 'IBM Plex Sans, sans-serif',
                  fontWeight: 500, letterSpacing: '0.05em',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {metrics.map(m => {
              const hasData = m.latency > 0 || m.detectRate > 0;
              return (
                <tr key={m.stage}>
                  <td style={{
                    padding: '5px 6px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 11, color: '#555',
                  }}>
                    {String(m.stage).padStart(2, '0')} {STAGE_NAMES[m.stage]}
                  </td>
                  <td style={{
                    padding: '5px 6px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 11, color: hasData ? '#c9c9c9' : '#333',
                    borderBottom: '1px solid #161616',
                  }}>
                    {m.latency.toFixed(1)}
                  </td>
                  <td style={{
                    padding: '5px 6px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 11,
                    color: m.detectRate >= 80 ? 'var(--green)' : m.detectRate > 0 ? 'var(--amber)' : '#333',
                    borderBottom: '1px solid #161616',
                  }}>
                    {m.detectRate.toFixed(1)}%
                  </td>
                  <td style={{
                    padding: '5px 6px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 11,
                    color: m.fpRate > 10 ? 'var(--red)' : '#555',
                    borderBottom: '1px solid #161616',
                  }}>
                    {m.fpRate.toFixed(2)}%
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* ── Bottom stats ─────────────────────────── */}
        <div style={{ marginTop: 10, borderTop: '1px solid #2a2a2a', paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: '#888', letterSpacing: '0.05em' }}>
              ATTACK SUCCESS RATE
            </span>
            <span className="mono" style={{
              fontSize: 14,
              color: successRate < 10 ? 'var(--green)' : successRate < 50 ? 'var(--amber)' : 'var(--red)',
              fontWeight: 700,
            }}>
              {successRate.toFixed(1)}%
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: '#888', letterSpacing: '0.05em' }}>
              SELF-HEALING DELTA
            </span>
            <span className="mono" style={{
              fontSize: 14,
              color: healDelta < 0 ? 'var(--green)' : healDelta > 0 ? 'var(--amber)' : '#555',
              fontWeight: 700,
            }}>
              {healDelta < 0 ? '' : healDelta > 0 ? '+' : ''}{healDelta.toFixed(1)}ms
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
