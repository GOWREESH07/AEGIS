import React, { useState } from 'react';
import { StatusBar }         from './components/StatusBar';
import { CouncilPanel }      from './components/CouncilPanel';
import { KillChainMap }      from './components/KillChainMap';
import { ThreatTable }       from './components/ThreatTable';
import { SurveillancePanel } from './components/SurveillancePanel';
import { DetectionLog }      from './components/DetectionLog';
import { MetricsPanel }      from './components/MetricsPanel';
import { RepoScanTab }       from './components/RepoScanTab';
import { useDefenseWS }      from './hooks/useDefenseWS';
import { useAegisAPI }       from './hooks/useAegisAPI';

function App() {
  const [activeTab, setActiveTab] = useState('live');

  const {
    latestVerdict,
    latestFeatures,
    stageStatus,
    detectionLog,
    wsStatus,
    stageMetrics,       // live — replaces metricsData
    latencyHistory,     // live — for sparkline
    attackSuccessRate,  // live — derived from WS event counts
    resetDefense,
  } = useDefenseWS();

  const {
    status,
    blocklist,
    escalations,
    resolveEscalation,
    healingStats,      // from /api/aegis/healing-stats
    metricsData,        // from /api/aegis/metrics
    toggleAegis,
    resetAegis,
  } = useAegisAPI();


  const handleReset = () => {
    resetAegis();
    resetDefense();
  };

  const handleExportIncident = () => {
    const host = typeof window !== 'undefined' ? (window.location.hostname || 'localhost') : 'localhost';
    window.open(`http://${host}:8000/api/aegis/incident/latest.md`, '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>

      <StatusBar
        status={status}
        wsStatus={wsStatus}
        toggleAegis={toggleAegis}
        resetAegis={handleReset}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onExportIncident={handleExportIncident}
      />

      {activeTab === 'reposcan' ? (
        <RepoScanTab onSwitchToLive={() => setActiveTab('live')} />
      ) : (
        <div style={{ flex: 1, display: 'grid', gridTemplateRows: '1fr 1fr', overflow: 'hidden' }}>

          {/* ── Top row: Council | KillChain | Threats ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr 350px', borderBottom: '1px solid #2a2a2a', overflow: 'hidden' }}>
            <div style={{ borderRight: '1px solid #2a2a2a', overflow: 'hidden' }}>
              <CouncilPanel verdict={latestVerdict} />
            </div>
            <div style={{ overflow: 'hidden' }}>
              <KillChainMap stageStatus={stageStatus} />
            </div>
            <div style={{ borderLeft: '1px solid #2a2a2a', overflow: 'hidden' }}>
              <ThreatTable blocklist={blocklist} escalations={escalations} onResolveEscalation={resolveEscalation} />
            </div>
          </div>

          {/* ── Bottom row: Surveillance+Log | Metrics ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', overflow: 'hidden' }}>
            <div style={{ display: 'flex', flexDirection: 'column', borderRight: '1px solid #2a2a2a', overflow: 'hidden' }}>
              <div style={{ flex: '0 0 45%', borderBottom: '1px solid #2a2a2a', overflow: 'hidden' }}>
                <SurveillancePanel features={latestFeatures} />
              </div>
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <DetectionLog logs={detectionLog} />
              </div>
            </div>
            <div style={{ overflow: 'hidden' }}>
              <MetricsPanel
                stageMetrics={stageMetrics}
                latencyHistory={latencyHistory}
                attackSuccessRate={attackSuccessRate}
                healingStats={healingStats}
                metricsData={metricsData}
              />
            </div>
          </div>


        </div>
      )}
    </div>
  );
}

export default App;
