/**
 * Shared placeholder component for pages not yet implemented.
 * Displays a professional "Phase X — Not Yet Implemented" state.
 */

import { Construction } from 'lucide-react';
import type React from 'react';

interface PlaceholderPageProps {
  title: string;
  phase: number;
  description: string;
  icon: React.ReactNode;
  plannedFeatures: string[];
  accentColor?: string;
}

export default function PlaceholderPage({
  title,
  phase,
  description,
  icon,
  plannedFeatures,
  accentColor = 'var(--color-cyan)',
}: PlaceholderPageProps) {
  return (
    <div
      className="not-implemented animate-fade-in"
      style={{ padding: '40px 20px' }}
    >
      {/* Icon */}
      <div
        style={{
          width: '72px',
          height: '72px',
          borderRadius: '16px',
          background: 'var(--color-bg-elevated)',
          border: '1px solid var(--color-border-dim)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: accentColor,
          opacity: 0.7,
          marginBottom: '4px',
        }}
      >
        {icon}
      </div>

      {/* Phase badge */}
      <span
        style={{
          fontSize: '11px',
          fontWeight: 600,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          color: accentColor,
          background: `rgba(6, 182, 212, 0.08)`,
          border: `1px solid rgba(6, 182, 212, 0.2)`,
          borderRadius: '20px',
          padding: '3px 12px',
        }}
      >
        Phase {phase} Feature
      </span>

      {/* Title */}
      <h2
        style={{
          margin: '4px 0',
          fontSize: '22px',
          fontWeight: 700,
          color: 'var(--color-text-primary)',
        }}
      >
        {title}
      </h2>

      {/* Description */}
      <p
        style={{
          maxWidth: '480px',
          fontSize: '14px',
          color: 'var(--color-text-muted)',
          lineHeight: 1.65,
          margin: '0 0 8px',
        }}
      >
        {description}
      </p>

      {/* Status notice */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '10px 16px',
          background: 'var(--color-bg-elevated)',
          border: '1px solid var(--color-border-dim)',
          borderRadius: '8px',
          fontSize: '13px',
          color: 'var(--color-text-muted)',
        }}
      >
        <Construction size={14} style={{ color: 'var(--color-amber)', flexShrink: 0 }} />
        <span>
          Not yet implemented — scheduled for{' '}
          <span style={{ color: 'var(--color-amber)', fontWeight: 600 }}>
            Phase {phase}
          </span>
        </span>
      </div>

      {/* Planned features */}
      {plannedFeatures.length > 0 && (
        <div
          style={{
            marginTop: '20px',
            padding: '16px 20px',
            background: 'var(--color-bg-card)',
            border: '1px solid var(--color-border-dim)',
            borderRadius: '8px',
            maxWidth: '420px',
            textAlign: 'left',
          }}
        >
          <div
            style={{
              fontSize: '11px',
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: 'var(--color-text-dim)',
              marginBottom: '10px',
            }}
          >
            Planned Deliverables
          </div>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {plannedFeatures.map((feat) => (
              <li
                key={feat}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '5px 0',
                  fontSize: '13px',
                  color: 'var(--color-text-muted)',
                  borderBottom: '1px solid var(--color-border-dim)',
                }}
              >
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: accentColor,
                    opacity: 0.5,
                    flexShrink: 0,
                  }}
                />
                {feat}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
