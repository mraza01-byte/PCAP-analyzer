/**
 * PCAP-MAN — Shared TypeScript Type Definitions
 * Phase 1: Navigation & UI types
 */

// ── Navigation ─────────────────────────────────────────────────

export type PageKey =
  | 'home'
  | 'captures'
  | 'hosts'
  | 'flows'
  | 'timeline'
  | 'investigations'
  | 'briefing'
  | 'settings';

export interface NavItem {
  key: PageKey;
  label: string;
  icon: string; // Lucide icon name
  description: string;
  phase: 1 | 2 | 3 | 4 | 5 | 6;
  implemented: boolean;
}

// ── Status ─────────────────────────────────────────────────────

export type StatusLevel = 'online' | 'offline' | 'checking' | 'degraded';

export interface StatusIndicator {
  label: string;
  status: StatusLevel;
  detail?: string;
}

// ── Metrics ────────────────────────────────────────────────────

export interface MetricCard {
  label: string;
  value: number;
  unit?: string;
  color: 'green' | 'cyan' | 'amber' | 'violet' | 'red';
  icon: string;
  trend?: 'up' | 'down' | 'stable';
}
