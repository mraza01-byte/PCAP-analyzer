import Header from '../components/Header';
import Sidebar from '../components/Sidebar';
import type { PageKey } from '../types';

interface MainLayoutProps {
  currentPage: PageKey;
  onNavigate: (page: PageKey) => void;
  children: React.ReactNode;
}

export default function MainLayout({ currentPage, onNavigate, children }: MainLayoutProps) {
  return (
    <div
      id="pcap-root"
      className="grid-bg"
      style={{
        display: 'flex',
        minHeight: '100vh',
        backgroundColor: 'var(--color-bg-deep)',
      }}
    >
      {/* Sidebar */}
      <Sidebar currentPage={currentPage} onNavigate={onNavigate} />

      {/* Main content area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <Header currentPage={currentPage} />
        <main
          id="pcap-main"
          style={{
            flex: 1,
            padding: '24px',
            overflowY: 'auto',
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
