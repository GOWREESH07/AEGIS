import React from 'react';

export function CouncilPanel({ verdict }) {
  // Extract per-analyst scores from CouncilVerdict.scores[]
  const scores = verdict?.scores || [];
  const getScore = (name) => scores.find(s => s.analyst_name === name)?.confidence ?? 0;

  const analysts = [
    { name: 'NETWORK',     key: 'NetworkAnalyst',    score: getScore('NetworkAnalyst'),    weight: 1.0 },
    { name: 'IDENTITY',    key: 'IdentityAnalyst',   score: getScore('IdentityAnalyst'),   weight: 1.0 },
    { name: 'AI-BEHAVIOR', key: 'AIBehaviorAnalyst', score: getScore('AIBehaviorAnalyst'), weight: 1.5 },
  ];

  const getBarColor = (score) => {
    if (score < 0.4) return 'var(--green)';
    if (score < 0.7) return 'var(--amber)';
    return 'var(--red)';
  };

  const actionColors = {
    allow:      'var(--green)',
    ratelimit:  'var(--amber)',
    block:      'var(--red)',
    quarantine: '#fca5a5',
  };

  const STAGE_TAGS = {
    1: { atlas: 'AML.T0006',     asi: 'ASI01' },
    2: { atlas: 'AML.T0043',     asi: 'ASI05' },
    3: { atlas: 'AML.T0051',     asi: 'ASI01' },
    4: { atlas: 'AML.T0029',     asi: 'ASI02' },
    5: { atlas: 'AML.T0048',     asi: 'ASI05' },
    6: { atlas: 'AML.T0054',     asi: 'ASI02' },
    7: { atlas: 'AML.T0051.001', asi: 'ASI06' },
    8: { atlas: 'AML.T0010',     asi: 'ASI04' },
    9: { atlas: 'AML.T0055',     asi: 'ASI10' },
  };
  const stageNum = verdict?.stage || 1;
  const fallbackTags = STAGE_TAGS[stageNum] || STAGE_TAGS[1];
  const atlasId = verdict?.atlas_id || fallbackTags.atlas;
  const asiId   = verdict?.asi_id   || fallbackTags.asi;

  // CouncilVerdict fields: weighted_confidence, verdict_ms, threshold, action
  const action    = verdict?.action             || 'allow';
  const conf      = verdict?.weighted_confidence ?? 0;
  const time      = verdict?.verdict_ms          ?? 0;
  const threshold = verdict?.threshold           ?? 0.55;

  return (
    <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <div style={{ fontSize: '11px', color: 'var(--muted)', letterSpacing: '0.08em' }}>
          COUNCIL DELIBERATION
        </div>
        <div className="mono" style={{ fontSize: '9px', color: 'var(--muted)' }} title="Pluggable GuardrailClassifier interface; learned model can be plugged in later">
          heuristic guardrail (rule-based)
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1 }}>
        {analysts.map((a) => (
          <div key={a.key} style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: 'var(--muted)', letterSpacing: '0.06em' }}>{a.name}</span>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <span style={{ fontSize: '10px', color: '#444' }}>×{a.weight.toFixed(1)}</span>
                <span className="mono" style={{ color: getBarColor(a.score), fontSize: '13px', fontWeight: 500 }}>
                  {a.score.toFixed(2)}
                </span>
              </div>
            </div>
            <div style={{ height: '5px', background: '#1a1a1a', border: '1px solid #2a2a2a' }}>
              <div style={{
                height: '100%',
                width: `${Math.min(100, a.score * 100)}%`,
                background: getBarColor(a.score),
                transition: 'width 0.25s ease, background 0.25s ease',
              }} />
            </div>
          </div>
        ))}
      </div>

      <div style={{ borderTop: '1px solid #2a2a2a', paddingTop: '14px', marginTop: '14px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: '10px', color: 'var(--muted)', marginBottom: '6px' }}>VERDICT</div>
            <div style={{
              display: 'inline-block',
              padding: '2px 8px',
              border: `1px solid ${actionColors[action] || 'var(--green)'}`,
              color: actionColors[action] || 'var(--green)',
              fontSize: '11px',
              fontWeight: 700,
              letterSpacing: '0.06em',
            }}>
              {action.toUpperCase()}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '6px' }}>
              THRESH {threshold.toFixed(2)}
            </div>
            <div className="mono" style={{ display: 'flex', gap: '4px', marginTop: '6px' }}>
              <span style={{ fontSize: '9px', padding: '1px 5px', border: '1px solid #2a2a2a', color: 'var(--amber)' }}>
                {atlasId}
              </span>
              <span style={{ fontSize: '9px', padding: '1px 5px', border: '1px solid #2a2a2a', color: 'var(--red)' }}>
                {asiId}
              </span>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '10px', color: 'var(--muted)', marginBottom: '4px' }}>WEIGHTED CONF</div>
            <div className="mono" style={{ fontSize: '22px', color: getBarColor(conf), lineHeight: 1 }}>
              {conf.toFixed(3)}
            </div>
            <div className="mono" style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '4px' }}>
              {time.toFixed(1)} ms
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
