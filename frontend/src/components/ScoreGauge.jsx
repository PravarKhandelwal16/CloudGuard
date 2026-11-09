import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export function ScoreGauge({ score, size = 'large' }) {
  if (score === null || score === undefined) {
    return <span style={{ color: '#64748b', fontSize: size === 'large' ? '1.75rem' : '1.1rem', fontWeight: 600 }}>—</span>;
  }

  let color = '#16a34a';
  let bgColor = '#dcfce7';
  let label = 'Good';
  let Icon = ShieldCheck;

  if (score < 50) {
    color = '#dc2626';
    bgColor = '#fee2e2';
    label = 'Critical Risk';
    Icon = ShieldAlert;
  } else if (score < 80) {
    color = '#d97706';
    bgColor = '#fef3c7';
    label = 'Moderate Risk';
    Icon = AlertTriangle;
  }

  if (size === 'small') {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          fontWeight: 700,
          color,
          fontSize: '0.95rem'
        }}
      >
        <span
          style={{
            display: 'inline-block',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: color
          }}
        />
        {score} / 100
      </span>
    );
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '12px',
        padding: '12px 18px',
        backgroundColor: bgColor,
        borderRadius: '8px',
        border: `1px solid ${color}33`
      }}
    >
      <Icon size={32} color={color} />
      <div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
          <span style={{ fontSize: '1.85rem', fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: '0.9rem', color: '#64748b', fontWeight: 600 }}>/ 100</span>
        </div>
        <div style={{ fontSize: '0.8rem', fontWeight: 600, color, marginTop: '2px' }}>
          {label} Security Score
        </div>
      </div>
    </div>
  );
}

