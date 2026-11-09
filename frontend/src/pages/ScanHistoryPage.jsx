import React, { useState, useEffect } from 'react';
import { History, FileCode, PlusCircle, AlertTriangle, ArrowRight, Search } from 'lucide-react';
import { api } from '../api/client';
import { ScoreGauge } from '../components/ScoreGauge';

export function ScanHistoryPage({ onNavigateToNewScan, onSelectScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.listScans();
      setScans(res.data || []);
    } catch (err) {
      setError(err.message || 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter((s) =>
    s.original_filename.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="history-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-desc">All past repository and project secret scans</p>
        </div>
        <button className="primary-btn" onClick={onNavigateToNewScan}>
          <PlusCircle size={18} />
          <span>New Scan</span>
        </button>
      </div>

      <div className="content-card">
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 className="card-title">Completed Scans ({scans.length})</h2>
            <span className="card-subtitle">Previous scan reports and security records</span>
          </div>

          {scans.length > 0 && (
            <div className="search-box">
              <Search size={16} color="#64748b" />
              <input
                type="text"
                placeholder="Search by project name..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          )}
        </div>

        {loading ? (
          <div className="page-loading">
            <div className="spinner" />
            <p>Loading history...</p>
          </div>
        ) : error ? (
          <div className="alert-box error" style={{ margin: '16px' }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="empty-state">
            <History size={40} color="#94a3b8" />
            <h3>{search ? 'No matching scans' : 'No scans performed yet'}</h3>
            <p>
              {search
                ? `No scans found matching "${search}".`
                : 'Upload your first ZIP archive to analyze your project code for secrets.'}
            </p>
            {!search && (
              <button className="primary-btn" onClick={onNavigateToNewScan} style={{ marginTop: '12px' }}>
                <PlusCircle size={16} />
                <span>Start First Scan</span>
              </button>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Project Name</th>
                  <th>Scan Date</th>
                  <th>Security Score</th>
                  <th>Findings</th>
                  <th>Files Scanned</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{ fontWeight: 600 }}>{scan.original_filename}</td>
                    <td style={{ color: '#64748b' }}>
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
                    </td>
                    <td>
                      <ScoreGauge score={scan.security_score} size="small" />
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{scan.total_findings}</span>
                      {scan.critical_count > 0 && (
                        <span style={{ color: '#dc2626', fontSize: '0.8rem', marginLeft: '6px' }}>
                          ({scan.critical_count} critical)
                        </span>
                      )}
                    </td>
                    <td style={{ color: '#64748b' }}>{scan.files_scanned}</td>
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
    </div>
  );
}

