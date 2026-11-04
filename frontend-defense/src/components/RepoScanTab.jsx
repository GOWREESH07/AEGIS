import React, { useState } from 'react';

const ASI_LABELS = {
  ASI01: 'Goal Hijack / Prompt Inj',
  ASI02: 'Excessive Agency / Tools',
  ASI03: 'Privilege Escalation',
  ASI04: 'Supply-Chain Compromise',
  ASI05: 'Insecure Code Exec',
  ASI06: 'Memory / Context Poison',
  ASI07: 'Multi-Agent Trust Abuse',
  ASI08: 'Slopsquat / Hallucination',
  ASI09: 'Insufficient Sandboxing',
  ASI10: 'Credential Exposure',
};

const API_HOST = typeof window !== 'undefined'
  ? `http://${window.location.hostname || 'localhost'}:8000`
  : 'http://localhost:8000';

export function RepoScanTab({ onSwitchToLive }) {
  const [url, setUrl] = useState('https://github.com/aegis-demo/vulnerable_repo');
  const [ref, setRef] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [showAllHighFixes, setShowAllHighFixes] = useState(false);
  const [compareMode, setCompareMode] = useState(false);
  const [compareReportB, setCompareReportB] = useState(null);
  const [simStatus, setSimStatus] = useState(null);

  const runScan = async (targetUrl = url) => {
    setLoading(true);
    setError(null);
    setSimStatus(null);
    try {
      const res = await fetch(`${API_HOST}/api/reposcan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, ref: ref || null }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || 'Scan failed');
      }
      const rep = data.report || data;
      setReport(rep);
      setHistory(prev => {
        const filtered = prev.filter(h => h.scan_id !== rep.scan_id);
        return [rep, ...filtered].slice(0, 10);
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async () => {
    if (!report) return;
    setSimStatus('Triggering sandboxed JadePuffer-sim against toy target...');
    try {
      const res = await fetch(`${API_HOST}/api/reposcan/${report.scan_id}/simulate`, {
        method: 'POST',
      });
      const data = await res.json();
      setSimStatus(`Triggered stages [${(data.mapped_stages || []).join(', ')}] against toy target.`);
      if (onSwitchToLive) {
        setTimeout(() => onSwitchToLive(), 1200);
      }
    } catch (e) {
      setSimStatus(`Simulation error: ${e.message}`);
    }
  };

  const getBandColor = (pct) => {
    if (pct >= 80) return 'var(--red)';
    if (pct >= 60) return '#f97316';
    if (pct >= 30) return 'var(--amber)';
    return 'var(--green)';
  };

  const getSevColor = (sev) => {
    if (sev === 'critical') return 'var(--red)';
    if (sev === 'high') return '#f97316';
    if (sev === 'medium') return 'var(--amber)';
    return 'var(--muted)';
  };

  const displayScore = report
    ? (showAllHighFixes ? report.projected_score_all_high_impact_pct : report.proneness_pct)
    : 0;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)' }}>
      {/* Top input bar */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid #2a2a2a',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        background: 'var(--panel-bg)',
      }}>
        <span className="mono" style={{ fontSize: 11, color: 'var(--accent)', fontWeight: 600 }}>
          GITHUB REPO URL
        </span>
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="mono"
          style={{
            flex: 1,
            background: '#0a0a0a',
            border: '1px solid #2a2a2a',
            color: 'var(--text)',
            padding: '6px 10px',
            fontSize: 12,
          }}
        />
        <input
          type="text"
          value={ref}
          onChange={e => setRef(e.target.value)}
          placeholder="ref / branch (opt)"
          className="mono"
          style={{
            width: 130,
            background: '#0a0a0a',
            border: '1px solid #2a2a2a',
            color: 'var(--text)',
            padding: '6px 8px',
            fontSize: 11,
          }}
        />
        <button
          onClick={() => runScan(url)}
          disabled={loading}
          style={{
            borderColor: 'var(--accent)',
            color: 'var(--accent)',
            fontWeight: 600,
            padding: '6px 14px',
          }}
        >
          {loading ? 'SCANNING...' : 'SCAN REPO'}
        </button>
        <button
          onClick={() => {
            setUrl('https://github.com/aegis-demo/vulnerable_repo');
            runScan('https://github.com/aegis-demo/vulnerable_repo');
          }}
          disabled={loading}
          style={{ fontSize: 10, padding: '6px 8px' }}
          title="Load vulnerable sample fixture (>=80%)"
        >
          VULN FIXTURE
        </button>
        <button
          onClick={() => {
            setUrl('https://github.com/aegis-demo/clean_repo');
            runScan('https://github.com/aegis-demo/clean_repo');
          }}
          disabled={loading}
          style={{ fontSize: 10, padding: '6px 8px' }}
          title="Load clean hardened fixture (<20%)"
        >
          CLEAN FIXTURE
        </button>
        <button
          onClick={() => setCompareMode(!compareMode)}
          style={{
            fontSize: 10,
            padding: '6px 10px',
            borderColor: compareMode ? 'var(--green)' : '#2a2a2a',
            color: compareMode ? 'var(--green)' : 'var(--muted)',
          }}
        >
          {compareMode ? 'EXIT COMPARE' : 'COMPARE'}
        </button>
      </div>

      {error && (
        <div style={{ padding: '10px 16px', background: 'rgba(239,68,68,0.12)', borderBottom: '1px solid var(--red)', color: 'var(--red)', fontSize: 12 }}>
          SCAN ERROR: {error}
        </div>
      )}

      {!report ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--muted)', flexDirection: 'column', gap: 10 }}>
          <div className="mono" style={{ fontSize: 14 }}>STATIC AI-ATTACK PRONENESS SCANNER (REPOSCAN)</div>
          <div style={{ fontSize: 12, maxWidth: 560, textAlign: 'center', lineHeight: 1.5 }}>
            Paste any public GitHub URL (`https://github.com/owner/repo`) or click <b>VULN FIXTURE</b> / <b>CLEAN FIXTURE</b> to run the Three-Analyst Council static analysis. Never executes repository code.
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* OWASP ASI01-ASI10 Heat-Row */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(10, 1fr)',
            borderBottom: '1px solid #2a2a2a',
            background: '#0b0b0b',
          }}>
            {Object.keys(ASI_LABELS).map(asi => {
              const count = report.asi_heatmap?.[asi] || 0;
              const bg = count >= 3
                ? 'rgba(239, 68, 68, 0.25)'
                : count >= 1
                ? 'rgba(245, 166, 35, 0.18)'
                : 'transparent';
              const fg = count >= 3 ? 'var(--red)' : count >= 1 ? 'var(--amber)' : '#444';
              return (
                <div
                  key={asi}
                  title={`${asi}: ${ASI_LABELS[asi]} (${count} findings)`}
                  style={{
                    padding: '6px 8px',
                    borderRight: '1px solid #1c1c1c',
                    background: bg,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                  }}
                >
                  <span className="mono" style={{ fontSize: 10, fontWeight: 700, color: fg }}>{asi}</span>
                  <span style={{ fontSize: 9, color: '#666', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '100%' }}>
                    {ASI_LABELS[asi]}
                  </span>
                  <span className="mono" style={{ fontSize: 11, color: fg, marginTop: 2 }}>{count}</span>
                </div>
              );
            })}
          </div>

          {/* Compare Banner if active */}
          {compareMode && (
            <div style={{
              padding: '8px 16px',
              borderBottom: '1px solid #2a2a2a',
              background: '#111',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 16,
              fontSize: 11,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>COMPARE MODE:</span>
                <span className="mono">
                  SCAN A: {report.repo_owner}/{report.repo_name} ({report.proneness_pct.toFixed(1)}% {report.risk_band})
                </span>
                <span>vs</span>
                <select
                  value={compareReportB?.scan_id || 'projected'}
                  onChange={e => {
                    if (e.target.value === 'projected') setCompareReportB(null);
                    else setCompareReportB(history.find(h => h.scan_id === e.target.value) || null);
                  }}
                  style={{ background: '#0a0a0a', color: 'var(--text)', border: '1px solid #2a2a2a', padding: '3px 6px', fontSize: 11 }}
                >
                  <option value="projected">After High-Impact Fixes ({report.projected_score_all_high_impact_pct.toFixed(1)}%)</option>
                  {history.filter(h => h.scan_id !== report.scan_id).map(h => (
                    <option key={h.scan_id} value={h.scan_id}>
                      {h.repo_owner}/{h.repo_name} [{h.scan_id}] ({h.proneness_pct.toFixed(1)}%)
                    </option>
                  ))}
                </select>
              </div>
              <div className="mono" style={{ color: 'var(--green)', fontWeight: 600 }}>
                DELTA: {(
                  (compareReportB ? compareReportB.proneness_pct : report.projected_score_all_high_impact_pct) -
                  report.proneness_pct
                ).toFixed(1)}%
              </div>
            </div>
          )}

          {/* Main 3-column body */}
          <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '320px 1fr 1fr', overflow: 'hidden' }}>
            {/* Column 1: Score + 3 Analysts + Arithmetic + Actions */}
            <div style={{ borderRight: '1px solid #2a2a2a', padding: 16, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.08em' }}>AI-ATTACK PRONENESS</div>
                  <div className="mono" style={{ fontSize: 36, fontWeight: 700, color: getBandColor(displayScore), lineHeight: 1.1, marginTop: 4 }}>
                    {displayScore.toFixed(1)}%
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{
                    display: 'inline-block',
                    padding: '3px 8px',
                    border: `1px solid ${getBandColor(displayScore)}`,
                    color: getBandColor(displayScore),
                    fontSize: 11,
                    fontWeight: 700,
                  }}>
                    {showAllHighFixes && displayScore < 30 ? 'LOW' : report.risk_band.toUpperCase()} RISK
                  </span>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', marginTop: 6 }}>
                    COV: {report.coverage_pct.toFixed(0)}% ({report.files_analysed}/{report.files_eligible} files)
                  </div>
                </div>
              </div>

              {/* Before / After gauge bar */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>
                  <span>BEFORE FIXES: {report.proneness_pct.toFixed(1)}%</span>
                  <span style={{ color: 'var(--green)' }}>AFTER HIGH FIXES: {report.projected_score_all_high_impact_pct.toFixed(1)}%</span>
                </div>
                <div style={{ height: 8, background: '#1a1a1a', border: '1px solid #2a2a2a', position: 'relative' }}>
                  <div style={{
                    position: 'absolute', left: 0, top: 0, bottom: 0,
                    width: `${Math.min(100, report.proneness_pct)}%`,
                    background: 'rgba(239, 68, 68, 0.35)',
                  }} />
                  <div style={{
                    position: 'absolute', left: 0, top: 0, bottom: 0,
                    width: `${Math.min(100, report.projected_score_all_high_impact_pct)}%`,
                    background: 'var(--green)',
                  }} />
                </div>
              </div>

              {/* 3 Analysts */}
              <div style={{ borderTop: '1px solid #2a2a2a', paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.08em' }}>REPOSCAN THREE-ANALYST COUNCIL</div>
                {(report.analysts || []).map(a => (
                  <div key={a.analyst} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                      <span style={{ color: 'var(--text)' }}>{a.name}</span>
                      <span className="mono" style={{ color: getBandColor(a.score * 100) }}>
                        ×{a.weight.toFixed(1)} | {a.score.toFixed(2)}
                      </span>
                    </div>
                    <div style={{ height: 5, background: '#1a1a1a', border: '1px solid #2a2a2a' }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.min(100, a.score * 100)}%`,
                        background: getBandColor(a.score * 100),
                      }} />
                    </div>
                    <div className="mono" style={{ fontSize: 9, color: '#666' }}>{a.formula_detail}</div>
                  </div>
                ))}
              </div>

              {/* Score Arithmetic box */}
              <div style={{ background: '#0a0a0a', border: '1px solid #2a2a2a', padding: 10 }}>
                <div style={{ fontSize: 9, color: 'var(--muted)', marginBottom: 4 }}>SCORE ARITHMETIC</div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--accent)', wordBreak: 'break-word' }}>
                  {report.score_arithmetic}
                </div>
              </div>

              {/* Explanation summary */}
              <div style={{ fontSize: 11, color: '#bbb', lineHeight: 1.45 }}>
                {report.summary_text}
              </div>

              {/* Action buttons: Simulate against AEGIS + Export */}
              <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <button
                  onClick={handleSimulate}
                  style={{
                    borderColor: 'var(--red)',
                    color: 'var(--red)',
                    fontWeight: 700,
                    padding: '8px 10px',
                    width: '100%',
                  }}
                >
                  SIMULATE AGAINST AEGIS (TOY TARGET)
                </button>
                {simStatus && (
                  <div className="mono" style={{ fontSize: 10, color: 'var(--amber)' }}>{simStatus}</div>
                )}
                <div style={{ display: 'flex', gap: 8 }}>
                  <a
                    href={`${API_HOST}/api/reposcan/${report.scan_id}/report.md`}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      flex: 1, textAlign: 'center', padding: '6px', border: '1px solid #2a2a2a',
                      color: 'var(--text)', textDecoration: 'none', fontSize: 10, fontFamily: 'var(--font-mono)',
                    }}
                  >
                    EXPORT .MD
                  </a>
                  <a
                    href={`${API_HOST}/api/reposcan/${report.scan_id}/report.pdf`}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      flex: 1, textAlign: 'center', padding: '6px', border: '1px solid #2a2a2a',
                      color: 'var(--text)', textDecoration: 'none', fontSize: 10, fontFamily: 'var(--font-mono)',
                    }}
                  >
                    EXPORT .PDF
                  </a>
                </div>
              </div>
            </div>

            {/* Column 2: Expandable Findings List */}
            <div style={{ borderRight: '1px solid #2a2a2a', padding: 16, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.08em', marginBottom: 10 }}>
                CONTRIBUTING FINDINGS ({report.findings?.length || 0})
              </div>
              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                {(report.findings || []).length === 0 ? (
                  <div style={{ color: 'var(--green)', fontSize: 12 }}>No high-risk AI or supply-chain findings detected.</div>
                ) : (
                  report.findings.map((f, idx) => {
                    const isOpen = expandedFinding === idx;
                    return (
                      <div
                        key={idx}
                        onClick={() => setExpandedFinding(isOpen ? null : idx)}
                        style={{
                          border: '1px solid #2a2a2a',
                          borderLeft: `3px solid ${getSevColor(f.severity)}`,
                          background: '#0d0d0d',
                          padding: '8px 10px',
                          cursor: 'pointer',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                          <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: getSevColor(f.severity) }}>
                            [{f.check_id}] {f.severity.toUpperCase()} (w={f.severity_weight})
                          </span>
                          <span className="mono" style={{ fontSize: 10, color: 'var(--muted)' }}>
                            {f.file}:{f.line}
                          </span>
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', marginTop: 4, fontWeight: 500 }}>
                          {f.title}
                        </div>
                        <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
                          {(f.asi_ids || []).map(asi => (
                            <span key={asi} className="mono" style={{
                              fontSize: 9, padding: '1px 5px', border: '1px solid #333', color: 'var(--accent)',
                            }}>
                              {asi}
                            </span>
                          ))}
                          {f.incident_ref && (
                            <span style={{ fontSize: 10, color: '#888' }}>• Resembles: {f.incident_ref}</span>
                          )}
                        </div>
                        {isOpen && (
                          <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #1f1f1f', fontSize: 11 }}>
                            <div className="mono" style={{ background: '#050505', padding: 6, color: '#e5e5e5', fontSize: 10, overflowX: 'auto', marginBottom: 6 }}>
                              {f.evidence}
                            </div>
                            <div style={{ color: '#aaa', lineHeight: 1.4 }}>{f.why_it_matters}</div>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Column 3: Prioritised Improvements & Snippets */}
            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.08em' }}>
                  PRIORITISED IMPROVEMENTS ({report.improvements?.length || 0})
                </span>
                <button
                  onClick={() => setShowAllHighFixes(!showAllHighFixes)}
                  style={{
                    fontSize: 10,
                    padding: '3px 8px',
                    borderColor: showAllHighFixes ? 'var(--green)' : 'var(--accent)',
                    color: showAllHighFixes ? 'var(--green)' : 'var(--accent)',
                  }}
                >
                  {showAllHighFixes
                    ? `SHOWING PROJECTED (${report.projected_score_all_high_impact_pct.toFixed(1)}%)`
                    : `APPLY ALL HIGH-IMPACT FIXES → ${report.projected_score_all_high_impact_pct.toFixed(1)}%`}
                </button>
              </div>
              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(report.improvements || []).map((imp, idx) => (
                  <div key={idx} style={{ border: '1px solid #2a2a2a', background: '#0d0d0d', padding: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--accent)', fontWeight: 700 }}>
                        FIX [{imp.finding_check_id}] {imp.file}:{imp.line}
                      </span>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--green)', fontWeight: 700 }}>
                        → {imp.projected_score_pct.toFixed(1)}% (−{imp.score_reduction_pct.toFixed(1)}%)
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text)', marginTop: 4 }}>{imp.description}</div>
                    <pre className="mono" style={{
                      marginTop: 6,
                      marginBottom: 0,
                      background: '#050505',
                      border: '1px solid #1c1c1c',
                      padding: 8,
                      fontSize: 10,
                      color: '#a7f3d0',
                      overflowX: 'auto',
                    }}>
                      {imp.snippet}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
