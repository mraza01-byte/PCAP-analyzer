interface SidebarProps {
  setPage: (page: string) => void;
}

export default function Sidebar({ setPage }: SidebarProps) {
  return (
    <aside>
      <h2>PCAP-MAN</h2>

      <ul>
        <li onClick={() => setPage("home")}>Home</li>
        <li onClick={() => setPage("captures")}>Captures</li>
        <li onClick={() => setPage("hosts")}>Hosts</li>
        <li onClick={() => setPage("flows")}>Flows</li>
        <li onClick={() => setPage("timeline")}>Timeline</li>
        <li onClick={() => setPage("investigations")}>
          Investigations
        </li>
        <li onClick={() => setPage("briefing")}>Briefing</li>
        <li onClick={() => setPage("settings")}>Settings</li>
      </ul>
    </aside>
  );
}