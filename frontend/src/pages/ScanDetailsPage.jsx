import React, { useState, useEffect } from 'react';
import { ArrowLeft, Shield, AlertTriangle, CheckCircle, ChevronDown, ChevronUp, FileCode, Clock, Info } from 'lucide-react';
import { api } from '../api/client';
import { ScoreGauge } from '../components/ScoreGauge';
import { SeverityBadge, MethodBadge } from '../components/SeverityBadge';

export function ScanDetailsPage({ scanId, onBack }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  useEffect(() => {
    loadScan();
  }, [scanId]);

  const loadScan = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getScan(scanId);
      setScan(res.data);
    } catch (err) {
      setError(err.message || 'Failed to load scan report.');
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner" />
        <p>Loading scan report...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="scan-details-page">
        <button className="back-link" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Back</span>
        </button>
        <div className="alert-box error" style={{ marginTop: '16px' }}>
          <AlertTriangle size={18} />
          <span>{error || 'Scan not found.'}</span>
        </div>
      </div>
    );
  }

  const findings = scan.findings || [];
  const filteredFindings = filterSeverity === 'ALL'
    ? findings
    : findings.filter((f) => f.severity.toUpperCase() === filterSeverity);

  return (
    <div className="scan-details-page">
      <div className="page-header" style={{ marginBottom: '16px' }}>
        <button className="back-link" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Back to Scans</span>
        </button>
      </div>

      {/* Top Report Header Card */}
      <div className="content-card report-header-card">
        <div className="report-main-info">
          <div>
            <div className="report-badge-row">
              <span className={`status-pill ${scan.status}`}>{scan.status}</span>
              <span className="meta-text">
                <Clock size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: '-2px' }} />
                {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
              </span>
              <span className="meta-text">&bull; ML Engine: {scan.ml_model_version}</span>
            </div>
            <h1 className="report-title">{scan.original_filename}</h1>
            <div className="report-stats-strip">
              <span><strong>{scan.files_scanned}</strong> files inspected</span>
              <span>&bull;</span>
              <span><strong>{scan.files_skipped}</strong> skipped</span>
              <span>&bull;</span>
              <span><strong>{scan.scan_duration_ms}</strong> ms duration</span>
            </div>
          </div>

          <div className="report-score-section">
            <ScoreGauge score={scan.security_score} size="large" />
          </div>
        </div>

        {/* Breakdown bar */}
        <div className="severity-counts-bar">
          <div className="sev-item critical">
            <span className="sev-count">{scan.critical_count}</span>
            <span className="sev-name">Critical (-30 ea)</span>
          </div>
          <div className="sev-item high">
            <span className="sev-count">{scan.high_count}</span>
            <span className="sev-name">High (-15 ea)</span>
          </div>
          <div className="sev-item medium">
            <span className="sev-count">{scan.medium_count}</span>
            <span className="sev-name">Medium (-7 ea)</span>
          </div>
          <div className="sev-item low">
            <span className="sev-count">{scan.low_count}</span>
            <span className="sev-name">Low (-2 ea)</span>
          </div>
        </div>

        <div className="score-explanation-note">
          <Info size={16} color="#64748b" style={{ flexShrink: 0, marginTop: '2px' }} />
          <span>
            <strong>Security Score Formula:</strong> <code>max(0, 100 - total severity deductions)</code>.
            Findings are potential exposed credentials identified via known regex patterns and the Random Forest ML classifier. CloudGuard masks all candidate values and never exposes raw secrets.
          </span>
        </div>
      </div>

      {/* Findings Table Section */}
      <div className="content-card" style={{ marginTop: '24px' }}>
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 className="card-title">Detected Findings ({findings.length})</h2>
            <span className="card-subtitle">Click any finding row to view masked evidence and remediation steps</span>
          </div>

          <div className="filter-buttons">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                type="button"
                className={`filter-btn ${filterSeverity === sev ? 'active' : ''}`}
                onClick={() => setFilterSeverity(sev)}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="empty-state">
            <CheckCircle size={40} color="#16a34a" />
            <h3>{filterSeverity === 'ALL' ? 'No secrets detected' : `No ${filterSeverity.toLowerCase()} findings`}</h3>
            <p>
              {filterSeverity === 'ALL'
                ? 'Great job! The scan completed without detecting any suspicious credentials.'
                : 'No findings match the selected severity filter.'}
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table findings-table">
              <thead>
                <tr>
                  <th style={{ width: '30px' }}></th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>File Location</th>
                  <th>Line</th>
                  <th>Detection Method</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding) => {
                  const isExpanded = expandedId === finding.id;
                  return (
                    <React.Fragment key={finding.id}>
                      <tr
                        className={`clickable-row ${isExpanded ? 'expanded' : ''}`}
                        onClick={() => toggleExpand(finding.id)}
                      >
                        <td>
                          {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                        </td>
                        <td style={{ fontWeight: 600 }}>{finding.category}</td>
                        <td>
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td>
                          <code className="path-code">{finding.file_path}</code>
                        </td>
                        <td style={{ textAlign: 'center', color: '#64748b' }}>
                          {finding.line_number || '—'}
                        </td>
                        <td>
                          <MethodBadge method={finding.detection_method} />
                        </td>
                        <td style={{ fontWeight: 600 }}>
                          {Math.round(finding.confidence * 100)}%
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="expansion-row">
                          <td colSpan="7">
                            <div className="finding-details-drawer">
                              <div className="detail-item">
                                <span className="detail-label">Masked Evidence:</span>
                                <code className="masked-value">{finding.masked_preview}</code>
                                <span className="mask-hint">(Raw secret masked for security)</span>
                              </div>

                              <div className="detail-item">
                                <span className="detail-label">Detection Reason:</span>
                                <span className="detail-text">{finding.reason}</span>
                              </div>

                              <div className="detail-item">
                                <span className="detail-label">Remediation Guidance:</span>
                                <div className="remediation-box">
                                  {finding.recommendation}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

