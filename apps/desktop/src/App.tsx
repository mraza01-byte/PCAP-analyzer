import { useState } from "react";

import MainLayout from "./layouts/MainLayout";

import Home from "./pages/Home";
import Captures from "./pages/Captures";
import Hosts from "./pages/Hosts";
import Flows from "./pages/Flows";
import Timeline from "./pages/Timeline";
import Investigations from "./pages/Investigations";
import Briefing from "./pages/Briefing";
import Settings from "./pages/Settings";

export default function App() {
  const [page, setPage] = useState("home");

  const renderPage = () => {
    switch (page) {
      case "captures":
        return <Captures />;

      case "hosts":
        return <Hosts />;

      case "flows":
        return <Flows />;

      case "timeline":
        return <Timeline />;

      case "investigations":
        return <Investigations />;

      case "briefing":
        return <Briefing />;

      case "settings":
        return <Settings />;

      default:
        return <Home />;
    }
  };

  return (
    <MainLayout setPage={setPage}>
      {renderPage()}
    </MainLayout>
  );
}