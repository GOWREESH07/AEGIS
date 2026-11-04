import React from 'react';
import StatusBar from './components/StatusBar';
import AttackConfig from './components/AttackConfig';
import KillChain from './components/KillChain';
import EventLog from './components/EventLog';
import { useAttackerWS } from './hooks/useAttackerWS';

export default function App() {
  const { events, runState, wsStatus } = useAttackerWS();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <StatusBar wsStatus={wsStatus} runId={runState.runId} />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <AttackConfig runState={runState} />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <KillChain runState={runState} events={events} />
          <EventLog events={events} />
        </div>
      </div>
    </div>
  );
}
