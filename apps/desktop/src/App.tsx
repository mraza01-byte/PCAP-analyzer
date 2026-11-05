import { useState } from 'react';
import MainLayout from './layouts/MainLayout';
import Briefing from './pages/Briefing';
import Captures from './pages/Captures';
import Flows from './pages/Flows';
import Home from './pages/Home';
import Hosts from './pages/Hosts';
import Investigations from './pages/Investigations';
import Settings from './pages/Settings';
import Timeline from './pages/Timeline';
import type { PageKey } from './types';

// ── Page Registry ──────────────────────────────────────────────

const PAGES: Record<PageKey, React.ComponentType> = {
  home:           Home,
  captures:       Captures,
  hosts:          Hosts,
  flows:          Flows,
  timeline:       Timeline,
  investigations: Investigations,
  briefing:       Briefing,
  settings:       Settings,
};

// ── App ────────────────────────────────────────────────────────

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageKey>('home');

  const PageComponent = PAGES[currentPage];

  return (
    <MainLayout currentPage={currentPage} onNavigate={setCurrentPage}>
      <PageComponent />
    </MainLayout>
  );
}
