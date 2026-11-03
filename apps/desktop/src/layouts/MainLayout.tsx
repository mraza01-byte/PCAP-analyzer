import { ReactNode } from "react";
import Sidebar from "../components/Sidebar";
import Header from "../components/Header";

interface MainLayoutProps {
  children: ReactNode;
}

export default function MainLayout({ children }: MainLayoutProps) {
  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar setPage={() => {}} />

      <div style={{ flex: 1 }}>
        <Header />

        <main>
          {children}
        </main>
      </div>
    </div>
  );
}