import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, FileCode, CheckCircle2, PlusCircle, ArrowRight, Clock, AlertOctagon, Cloud } from 'lucide-react';
import { api } from '../api/client';
import { ScoreGauge } from '../components/ScoreGauge';
import { SeverityBadge } from '../components/SeverityBadge';

export function OverviewPage({ onNavigateToNewScan, onNavigateToCloudSecurity, onSelectScan }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getDashboardSummary();
      setSummary(res.data);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard summary.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner" />
        <p>Loading security overview...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert-box error" style={{ margin: '24px' }}>
        <AlertTriangle size={18} />
        <span>{error}</span>
        <button onClick={loadDashboard} className="secondary-btn" style={{ marginLeft: 'auto' }}>Retry</button>
      </div>
    );
  }

  const {
    total_scans = 0,
    total_findings = 0,
    critical_findings = 0,
    latest_security_score = null,
    recent_scans = [],
    recent_high_risk_findings = []
  } = summary || {};

  return (
    <div className="overview-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-desc">Project health summary and credential detection metrics</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          {onNavigateToCloudSecurity && (
            <button className="secondary-btn" onClick={onNavigateToCloudSecurity}>
              <Cloud size={16} color="#2563eb" />
              <span>Cloud Auditor</span>
            </button>
          )}
          <button className="primary-btn" onClick={onNavigateToNewScan}>
            <PlusCircle size={18} />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-label">Total Scans</span>
            <FileCode size={20} color="#2563eb" />
          </div>
          <div className="metric-value">{total_scans}</div>
          <div className="metric-hint">Uploaded project archives</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-label">Total Findings</span>
            <AlertTriangle size={20} color="#d97706" />
          </div>
          <div className="metric-value">{total_findings}</div>
          <div className="metric-hint">Potential exposed credentials</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-label">Critical Findings</span>
            <AlertOctagon size={20} color="#dc2626" />
          </div>
          <div className="metric-value" style={{ color: critical_findings > 0 ? '#dc2626' : 'inherit' }}>
            {critical_findings}
          </div>
          <div className="metric-hint">High priority remediation items</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-label">Latest Security Score</span>
            <Shield size={20} color="#16a34a" />
          </div>
          <div className="metric-value">
            <ScoreGauge score={latest_security_score} size="small" />
          </div>
          <div className="metric-hint">Base 100 minus severity deductions</div>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Recent Scans Table */}
        <div className="content-card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Recent Scans</h2>
              <span className="card-subtitle">Last 5 scanned projects</span>
            </div>
          </div>

          {recent_scans.length === 0 ? (
            <div className="empty-state">
              <FileCode size={36} color="#94a3b8" />
              <h3>No scans yet</h3>
              <p>Upload a project ZIP file to scan for exposed secrets.</p>
              <button className="primary-btn" onClick={onNavigateToNewScan} style={{ marginTop: '12px' }}>
                <PlusCircle size={16} />
                <span>Upload First Project</span>
              </button>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Project</th>
                    <th>Date</th>
                    <th>Score</th>
                    <th>Findings</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {recent_scans.map((scan) => (
                    <tr key={scan.id}>
                      <td style={{ fontWeight: 600 }}>{scan.original_filename}</td>
                      <td style={{ color: '#64748b' }}>
                        {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td>
                        <ScoreGauge score={scan.security_score} size="small" />
                      </td>
                      <td>
                        <span style={{ fontWeight: 600 }}>{scan.total_findings}</span>
                        {scan.critical_count > 0 && (
                          <span style={{ color: '#dc2626', fontSize: '0.8rem', marginLeft: '6px' }}>
                            ({scan.critical_count} crit)
                          </span>
                        )}
                      </td>
                      <td>
                        <span className={`status-pill ${scan.status}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className="link-btn"
                          onClick={() => onSelectScan(scan.id)}
                        >
                          View Report &rarr;
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent High-Risk Findings List */}
        <div className="content-card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Recent High-Risk Findings</h2>
              <span className="card-subtitle">Critical and High priority alerts</span>
            </div>
          </div>

          {recent_high_risk_findings.length === 0 ? (
            <div className="empty-state">
              <CheckCircle2 size={36} color="#16a34a" />
              <h3>No high-risk findings</h3>
              <p>No critical or high severity secrets flagged in your recent scans.</p>
            </div>
          ) : (
            <div className="findings-mini-list">
              {recent_high_risk_findings.map((f, idx) => (
                <div key={idx} className="finding-mini-item">
                  <div className="finding-mini-top">
                    <SeverityBadge severity={f.severity} />
                    <span className="finding-category">{f.category}</span>
                    <button
                      className="link-btn"
                      onClick={() => onSelectScan(f.scan_id)}
                      style={{ marginLeft: 'auto', fontSize: '0.8rem' }}
                    >
                      Report &rarr;
                    </button>
                  </div>
                  <div className="finding-mini-path" title={f.file_path}>
                    <code>{f.file_path}</code>
                    {f.line_number && <span>:{f.line_number}</span>}
                  </div>
                  <div className="finding-mini-mask">
                    Masked preview: <code>{f.masked_preview}</code>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

