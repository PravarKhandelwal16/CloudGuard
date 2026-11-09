import React from 'react';

export function SeverityBadge({ severity }) {
  const sev = (severity || 'Medium').toLowerCase();
  
  const styles = {
    critical: { bg: '#fee2e2', text: '#991b1b', border: '#fecaca' },
    high: { bg: '#ffedd5', text: '#9a3412', border: '#fed7aa' },
    medium: { bg: '#fef3c7', text: '#92400e', border: '#fde68a' },
    low: { bg: '#f1f5f9', text: '#475569', border: '#e2e8f0' }
  };

  const style = styles[sev] || styles.medium;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: '600',
        backgroundColor: style.bg,
        color: style.text,
        border: `1px solid ${style.border}`,
        textTransform: 'uppercase',
        letterSpacing: '0.025em'
      }}
    >
      {severity}
    </span>
  );
}

export function MethodBadge({ method }) {
  const isHybrid = method === 'Rule + ML';
  const isML = method === 'ML';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '0.75rem',
        fontWeight: '500',
        backgroundColor: isHybrid ? '#e0e7ff' : isML ? '#f3e8ff' : '#f8fafc',
        color: isHybrid ? '#3730a3' : isML ? '#6b21a8' : '#334155',
        border: '1px solid #cbd5e1'
      }}
    >
      {method}
    </span>
  );
}

