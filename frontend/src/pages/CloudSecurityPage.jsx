import React, { useState, useEffect } from 'react';
import {
  Cloud,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCw,
  Server,
  Key,
  Lock,
  ExternalLink,
  ChevronRight,
  Info,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  History,
  Layers,
  Search,
  Filter,
  Eye,
  X
} from 'lucide-react';
import { api } from '../api/client';
import { ScoreGauge } from '../components/ScoreGauge';
import { SeverityBadge, StatusBadge } from '../components/SeverityBadge';

export function CloudSecurityPage() {
  const [activeTab, setActiveTab] = useState('overview'); // overview, connect, history
  const [summary, setSummary] = useState(null);
  const [currentAssessment, setCurrentAssessment] = useState(null);
  const [historyList, setHistoryList] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [simulationScenario, setSimulationScenario] = useState('hardened');
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState(null);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [copiedCli, setCopiedCli] = useState(false);

  // Filters for findings table
  const [searchQuery, setSearchQuery] = useState('');
  const [serviceFilter, setServiceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Connection form state
  const [connectionForm, setConnectionForm] = useState({
    account_id: '',
    role_arn: '',
    external_id: '',
    region: 'ap-south-1',
    alias: ''
  });

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    setError('');
    try {
      const summaryRes = await api.getCloudSummary();
      setSummary(summaryRes.data);

      if (summaryRes.data?.latest_assessment) {
        // Load full latest assessment
        const scanRes = await api.getCloudScan(summaryRes.data.latest_assessment.id);
        setCurrentAssessment(scanRes.data);
      }

      const histRes = await api.listCloudHistory();
      setHistoryList(histRes.data || []);

      // If user has saved connections, prefill form with first one
      if (summaryRes.data?.connections?.length > 0) {
        const saved = summaryRes.data.connections[0];
        setConnectionForm({
          account_id: saved.account_id || '',
          role_arn: saved.role_arn || '',
          external_id: '',
          region: saved.region || 'ap-south-1',
          alias: saved.alias || ''
        });
      }
    } catch (err) {
      setError(err.message || 'Failed to load cloud security data.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunDemoScan = async (selectedScenario) => {
    const sc = typeof selectedScenario === 'string' ? selectedScenario : simulationScenario;
    setScanning(true);
    setError('');
    setSuccessMsg('');
    try {
      const res = await api.runCloudDemoScan(sc, connectionForm.region || 'ap-south-1');
      setCurrentAssessment(res.data);
      setActiveTab('overview');
      setSuccessMsg(`Simulated cloud security audit completed: ${res.data?.simulation_scenario || sc}!`);
      // Refresh history
      const histRes = await api.listCloudHistory();
      setHistoryList(histRes.data || []);
    } catch (err) {
      setError(err.message || 'Simulation audit failed.');
    } finally {
      setScanning(false);
    }
  };

  const handleTestConnection = async (e) => {
    e.preventDefault();
    setTestingConnection(true);
    setConnectionTestResult(null);
    setError('');
    try {
      const res = await api.testCloudConnection(connectionForm);
      setConnectionTestResult(res);
      setSuccessMsg('STS AssumeRole connection verified successfully.');
    } catch (err) {
      setConnectionTestResult({
        success: false,
        error: err.message || 'Connection test failed. Please verify the IAM role trust policy.'
      });
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSaveConnection = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    try {
      await api.connectCloudAccount(connectionForm);
      setSuccessMsg('AWS Account connection saved successfully.');
      const summaryRes = await api.getCloudSummary();
      setSummary(summaryRes.data);
    } catch (err) {
      setError(err.message || 'Failed to save connection.');
    }
  };

  const handleRunLiveScan = async () => {
    setScanning(true);
    setError('');
    setSuccessMsg('');
    try {
      const res = await api.runCloudScan(connectionForm);
      setCurrentAssessment(res.data);
      setActiveTab('overview');
      setSuccessMsg('Live AWS Cloud Security Audit completed successfully!');
      const histRes = await api.listCloudHistory();
      setHistoryList(histRes.data || []);
    } catch (err) {
      setError(err.message || 'Live AWS scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const handleSelectHistoryScan = async (scanId) => {
    setLoading(true);
    try {
      const res = await api.getCloudScan(scanId);
      setCurrentAssessment(res.data);
      setActiveTab('overview');
    } catch (err) {
      setError(err.message || 'Failed to load historical assessment.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  // Filtered findings
  const findings = currentAssessment?.findings || [];
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      searchQuery === '' ||
      f.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.resource_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.service?.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesService = serviceFilter === 'ALL' || f.service?.toUpperCase() === serviceFilter;
    const matchesSeverity = severityFilter === 'ALL' || f.severity?.toUpperCase() === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status?.toUpperCase() === statusFilter;

    return matchesSearch && matchesService && matchesSeverity && matchesStatus;
  });

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner" />
        <p>Loading Cloud Security Auditor...</p>
      </div>
    );
  }

  return (
    <div className="cloud-security-page" style={{ paddingBottom: '60px' }}>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cloud size={28} color="#2563eb" />
            <h1 className="page-title">Cloud Security Auditor</h1>
          </div>
          <p className="page-desc">
            Assess AWS cloud infrastructure for misconfigurations and receive actionable remediation guidance.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <select
            value={simulationScenario}
            onChange={(e) => {
              setSimulationScenario(e.target.value);
              handleRunDemoScan(e.target.value);
            }}
            disabled={scanning}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid var(--border)',
              fontSize: '0.85rem',
              backgroundColor: 'var(--bg-card)',
              color: 'var(--text-primary)',
              cursor: 'pointer'
            }}
            title="Choose a simulated environment scenario"
          >
            <option value="hardened">🛡️ Hardened Production (Score: 91/100)</option>
            <option value="compliant">✅ CIS Compliant (Score: 100/100)</option>
            <option value="high_risk">⚠️ High-Risk Environment (Score: 0/100)</option>
          </select>

          <button
            className="secondary-btn"
            onClick={() => handleRunDemoScan(simulationScenario)}
            disabled={scanning}
            title="Run simulated audit with selected scenario"
          >
            {scanning ? <div className="spinner-small" /> : <Play size={16} color="#2563eb" />}
            <span>Run Simulation</span>
          </button>

          <button
            className="primary-btn"
            onClick={() => setActiveTab('connect')}
          >
            <Server size={16} />
            <span>Connect & Scan AWS</span>
          </button>
        </div>
      </div>

      {/* Global Alerts */}
      {error && (
        <div className="alert-box error" style={{ marginBottom: '20px' }}>
          <AlertTriangle size={18} />
          <span>{error}</span>
          <button onClick={() => setError('')} className="text-btn" style={{ marginLeft: 'auto', color: 'inherit' }}>
            ✕
          </button>
        </div>
      )}

      {successMsg && (
        <div className="alert-box success" style={{ marginBottom: '20px', backgroundColor: '#dcfce7', borderColor: '#bbf7d0', color: '#166534' }}>
          <CheckCircle2 size={18} />
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg('')} className="text-btn" style={{ marginLeft: 'auto', color: 'inherit' }}>
            ✕
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border)', marginBottom: '24px' }}>
        <button
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
          style={{
            padding: '10px 16px',
            border: 'none',
            background: 'none',
            borderBottom: activeTab === 'overview' ? '2px solid #2563eb' : '2px solid transparent',
            color: activeTab === 'overview' ? '#2563eb' : 'var(--text-secondary)',
            fontWeight: activeTab === 'overview' ? 600 : 500,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Shield size={16} />
          <span>Security Overview & Findings</span>
        </button>

        <button
          className={`tab-btn ${activeTab === 'connect' ? 'active' : ''}`}
          onClick={() => setActiveTab('connect')}
          style={{
            padding: '10px 16px',
            border: 'none',
            background: 'none',
            borderBottom: activeTab === 'connect' ? '2px solid #2563eb' : '2px solid transparent',
            color: activeTab === 'connect' ? '#2563eb' : 'var(--text-secondary)',
            fontWeight: activeTab === 'connect' ? 600 : 500,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Server size={16} />
          <span>AWS Account Connection</span>
        </button>

        <button
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
          style={{
            padding: '10px 16px',
            border: 'none',
            background: 'none',
            borderBottom: activeTab === 'history' ? '2px solid #2563eb' : '2px solid transparent',
            color: activeTab === 'history' ? '#2563eb' : 'var(--text-secondary)',
            fontWeight: activeTab === 'history' ? 600 : 500,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <History size={16} />
          <span>Audit History ({historyList.length})</span>
        </button>
      </div>

      {/* TAB 1: OVERVIEW & FINDINGS */}
      {activeTab === 'overview' && (
        <>
          {!currentAssessment ? (
            <div className="content-card" style={{ textAlign: 'center', padding: '60px 20px' }}>
              <Cloud size={48} color="#94a3b8" style={{ margin: '0 auto 16px' }} />
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px' }}>
                No Cloud Security Assessment Executed Yet
              </h2>
              <p style={{ color: 'var(--text-muted)', maxWidth: '520px', margin: '0 auto 24px' }}>
                Run the local simulation mode to test the security rules engine against realistic AWS configurations, or connect your AWS account using a read-only IAM role.
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
                <button className="primary-btn" onClick={handleRunDemoScan} disabled={scanning}>
                  <Play size={16} />
                  <span>Launch Demo Simulation</span>
                </button>
                <button className="secondary-btn" onClick={() => setActiveTab('connect')}>
                  <Server size={16} />
                  <span>Configure AWS Connection</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Simulation Mode Banner */}
              {currentAssessment.is_simulation && (
                <div
                  style={{
                    backgroundColor: '#fffbeb',
                    border: '1px solid #fde68a',
                    borderRadius: '8px',
                    padding: '12px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    marginBottom: '20px',
                    color: '#92400e'
                  }}
                >
                  <Info size={20} color="#d97706" style={{ flexShrink: 0 }} />
                  <div>
                    <strong style={{ display: 'block', fontSize: '0.9rem' }}>
                      DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS
                    </strong>
                    <span style={{ fontSize: '0.82rem' }}>
                      This audit executed using realistic simulated AWS configurations. The real AWS assessment and simulation mode share the exact same rules and finding generation logic.
                    </span>
                  </div>
                </div>
              )}

              {/* Incomplete Assessment Alert */}
              {currentAssessment.coverage_status !== 'complete' && (
                <div
                  style={{
                    backgroundColor: '#fef2f2',
                    border: '1px solid #fecaca',
                    borderRadius: '8px',
                    padding: '12px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    marginBottom: '20px',
                    color: '#991b1b'
                  }}
                >
                  <AlertTriangle size={20} color="#dc2626" style={{ flexShrink: 0 }} />
                  <div>
                    <strong style={{ display: 'block', fontSize: '0.9rem' }}>
                      Incomplete Assessment Coverage
                    </strong>
                    <span style={{ fontSize: '0.82rem' }}>
                      {currentAssessment.coverage_notes || 'Some AWS API calls failed due to insufficient permissions. Unassessed services are not counted as secure.'}
                    </span>
                  </div>
                </div>
              )}

              {/* Assessment Posture Overview Header */}
              <div className="content-card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <ScoreGauge score={currentAssessment.security_score} size="large" />
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>
                          {currentAssessment.simulation_scenario || `Account: ${currentAssessment.account_id}`}
                        </h2>
                        {currentAssessment.is_simulation ? (
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, backgroundColor: '#fef3c7', color: '#92400e', padding: '2px 8px', borderRadius: '4px' }}>
                            SIMULATED
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, backgroundColor: '#dcfce7', color: '#166534', padding: '2px 8px', borderRadius: '4px' }}>
                            LIVE AWS
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Account: <strong>{currentAssessment.account_id}</strong> • Region: <strong>{currentAssessment.region}</strong> • Coverage: <span style={{ textTransform: 'capitalize', fontWeight: 600 }}>{currentAssessment.coverage_status}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {currentAssessment.is_simulation ? (
                      <>
                        <select
                          value={simulationScenario}
                          onChange={(e) => {
                            setSimulationScenario(e.target.value);
                            handleRunDemoScan(e.target.value);
                          }}
                          disabled={scanning}
                          style={{
                            padding: '6px 10px',
                            borderRadius: '6px',
                            border: '1px solid var(--border)',
                            fontSize: '0.82rem',
                            backgroundColor: 'var(--bg-card)'
                          }}
                        >
                          <option value="hardened">🛡️ Hardened (91)</option>
                          <option value="compliant">✅ Compliant (100)</option>
                          <option value="high_risk">⚠️ High-Risk (0)</option>
                        </select>
                        <button className="secondary-btn" onClick={() => handleRunDemoScan(simulationScenario)} disabled={scanning}>
                          <RotateCw size={14} className={scanning ? 'spin' : ''} />
                          <span>Re-run</span>
                        </button>
                      </>
                    ) : (
                      <button className="primary-btn" onClick={handleRunLiveScan} disabled={scanning}>
                        <RotateCw size={14} className={scanning ? 'spin' : ''} />
                        <span>Re-run Live Audit</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">Resources Assessed</span>
                    <Layers size={18} color="#2563eb" />
                  </div>
                  <div className="metric-value">{currentAssessment.total_resources_assessed}</div>
                  <div className="metric-hint">S3, IAM, SGs, Trails, Storage</div>
                </div>

                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">Checks Passed</span>
                    <CheckCircle2 size={18} color="#16a34a" />
                  </div>
                  <div className="metric-value" style={{ color: '#16a34a' }}>
                    {currentAssessment.checks_passed}
                  </div>
                  <div className="metric-hint">Baseline security met</div>
                </div>

                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">Critical Findings</span>
                    <ShieldAlert size={18} color="#dc2626" />
                  </div>
                  <div className="metric-value" style={{ color: currentAssessment.critical_count > 0 ? '#dc2626' : 'inherit' }}>
                    {currentAssessment.critical_count}
                  </div>
                  <div className="metric-hint">-30 pts each (Immediate risk)</div>
                </div>

                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">High Findings</span>
                    <AlertTriangle size={18} color="#ea580c" />
                  </div>
                  <div className="metric-value" style={{ color: currentAssessment.high_count > 0 ? '#ea580c' : 'inherit' }}>
                    {currentAssessment.high_count}
                  </div>
                  <div className="metric-hint">-15 pts each</div>
                </div>

                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">Medium Findings</span>
                    <AlertTriangle size={18} color="#d97706" />
                  </div>
                  <div className="metric-value" style={{ color: currentAssessment.medium_count > 0 ? '#d97706' : 'inherit' }}>
                    {currentAssessment.medium_count}
                  </div>
                  <div className="metric-hint">-7 pts each</div>
                </div>

                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">Low Findings</span>
                    <Info size={18} color="#64748b" />
                  </div>
                  <div className="metric-value">{currentAssessment.low_count}</div>
                  <div className="metric-hint">-2 pts each</div>
                </div>
              </div>

              {/* Service Summaries Pills */}
              {currentAssessment.resource_summaries?.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginBottom: '24px' }}>
                  {currentAssessment.resource_summaries.map((s, idx) => (
                    <div
                      key={idx}
                      style={{
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border)',
                        borderRadius: '6px',
                        padding: '6px 12px',
                        fontSize: '0.8rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}
                    >
                      <strong style={{ color: 'var(--text-primary)' }}>{s.service}:</strong>
                      <span>{s.total} {s.resource_type}s</span>
                      <span style={{ color: '#16a34a' }}>✓ {s.passed}</span>
                      {s.failed > 0 && <span style={{ color: '#dc2626' }}>✗ {s.failed}</span>}
                    </div>
                  ))}
                </div>
              )}

              {/* Findings Section */}
              <div className="content-card">
                <div className="card-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <h2 className="card-title">Security Findings & Baseline Checks</h2>
                    <p className="card-subtitle">
                      Showing {filteredFindings.length} of {findings.length} total findings
                    </p>
                  </div>

                  {/* Filter Controls */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                    {/* Search */}
                    <div style={{ position: 'relative' }}>
                      <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: '#94a3b8' }} />
                      <input
                        type="text"
                        placeholder="Search resource or title..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={{
                          padding: '6px 10px 6px 30px',
                          borderRadius: '6px',
                          border: '1px solid var(--border)',
                          fontSize: '0.85rem'
                        }}
                      />
                    </div>

                    {/* Service filter */}
                    <select
                      value={serviceFilter}
                      onChange={(e) => setServiceFilter(e.target.value)}
                      style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.85rem' }}
                    >
                      <option value="ALL">All Services</option>
                      <option value="S3">S3</option>
                      <option value="IAM">IAM</option>
                      <option value="SECURITYGROUP">Security Groups</option>
                      <option value="CLOUDTRAIL">CloudTrail</option>
                      <option value="EBS">EBS Volumes</option>
                      <option value="RDS">RDS Databases</option>
                    </select>

                    {/* Severity filter */}
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.85rem' }}
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                      <option value="INFORMATIONAL">Informational</option>
                    </select>

                    {/* Status filter */}
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.85rem' }}
                    >
                      <option value="ALL">All Statuses</option>
                      <option value="FAILED">Failed</option>
                      <option value="PASSED">Passed</option>
                      <option value="WARNING">Warning</option>
                      <option value="NOT ASSESSED">Not Assessed</option>
                    </select>
                  </div>
                </div>

                {/* Findings Table */}
                <div style={{ overflowX: 'auto' }}>
                  <table className="findings-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '12px 10px' }}>Severity</th>
                        <th style={{ padding: '12px 10px' }}>Status</th>
                        <th style={{ padding: '12px 10px' }}>Service</th>
                        <th style={{ padding: '12px 10px' }}>Security Check & Issue</th>
                        <th style={{ padding: '12px 10px' }}>Resource ID</th>
                        <th style={{ padding: '12px 10px' }}>Region</th>
                        <th style={{ padding: '12px 10px', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.length === 0 ? (
                        <tr>
                          <td colSpan="7" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                            No findings match the selected filters.
                          </td>
                        </tr>
                      ) : (
                        filteredFindings.map((f, i) => (
                          <tr
                            key={f.id || i}
                            style={{
                              borderBottom: '1px solid var(--border)',
                              backgroundColor: f.severity === 'CRITICAL' && f.status === 'FAILED' ? '#fff5f5' : 'transparent',
                              cursor: 'pointer'
                            }}
                            onClick={() => setSelectedFinding(f)}
                          >
                            <td style={{ padding: '10px' }}>
                              <SeverityBadge severity={f.severity} />
                            </td>
                            <td style={{ padding: '10px' }}>
                              <StatusBadge status={f.status} />
                            </td>
                            <td style={{ padding: '10px' }}>
                              <span style={{ fontWeight: 600, color: '#3b82f6' }}>{f.service}</span>
                            </td>
                            <td style={{ padding: '10px' }}>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</div>
                              <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', marginTop: '2px' }}>
                                {f.description?.slice(0, 90)}{f.description?.length > 90 ? '...' : ''}
                              </div>
                            </td>
                            <td style={{ padding: '10px' }}>
                              <code style={{ fontSize: '0.8rem', backgroundColor: '#f1f5f9', padding: '2px 6px', borderRadius: '4px' }}>
                                {f.resource_id}
                              </code>
                            </td>
                            <td style={{ padding: '10px', color: 'var(--text-muted)' }}>
                              {f.region || currentAssessment.region}
                            </td>
                            <td style={{ padding: '10px', textAlign: 'right' }}>
                              <button
                                className="link-btn"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedFinding(f);
                                }}
                              >
                                View Details
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </>
      )}

      {/* TAB 2: AWS ACCOUNT CONNECTION */}
      {activeTab === 'connect' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1.4fr) minmax(280px, 1fr)', gap: '24px' }}>
          <div className="content-card">
            <h2 className="card-title" style={{ marginBottom: '8px' }}>
              Connect AWS Account (STS AssumeRole)
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '20px' }}>
              CloudGuard connects to your AWS account using temporary credentials generated by AWS Security Token Service (STS). Permanent access keys are never requested or stored.
            </p>

            <form onSubmit={handleTestConnection}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px' }}>
                  AWS Account ID (12 digits) *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 123456789012"
                  value={connectionForm.account_id}
                  onChange={(e) => setConnectionForm({ ...connectionForm, account_id: e.target.value })}
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}
                />
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px' }}>
                  IAM Role ARN *
                </label>
                <input
                  type="text"
                  required
                  placeholder="arn:aws:iam::123456789012:role/CloudGuardAuditorRole"
                  value={connectionForm.role_arn}
                  onChange={(e) => setConnectionForm({ ...connectionForm, role_arn: e.target.value })}
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px' }}>
                    AWS Region
                  </label>
                  <select
                    value={connectionForm.region}
                    onChange={(e) => setConnectionForm({ ...connectionForm, region: e.target.value })}
                    style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}
                  >
                    <option value="ap-south-1">Asia Pacific (Mumbai) ap-south-1</option>
                    <option value="us-east-1">US East (N. Virginia) us-east-1</option>
                    <option value="us-east-2">US East (Ohio) us-east-2</option>
                    <option value="us-west-2">US West (Oregon) us-west-2</option>
                    <option value="eu-west-1">Europe (Ireland) eu-west-1</option>
                    <option value="ap-southeast-1">Asia Pacific (Singapore) ap-southeast-1</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px' }}>
                    External ID (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. cloudguard-client-id"
                    value={connectionForm.external_id}
                    onChange={(e) => setConnectionForm({ ...connectionForm, external_id: e.target.value })}
                    style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}
                  />
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px' }}>
                  Account Alias / Label (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. Production Infrastructure"
                  value={connectionForm.alias}
                  onChange={(e) => setConnectionForm({ ...connectionForm, alias: e.target.value })}
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}
                />
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
                <button
                  type="submit"
                  className="secondary-btn"
                  disabled={testingConnection || scanning}
                >
                  {testingConnection ? <div className="spinner-small" /> : <Lock size={16} />}
                  <span>Test Connection</span>
                </button>

                <button
                  type="button"
                  className="secondary-btn"
                  onClick={handleSaveConnection}
                  disabled={testingConnection || scanning}
                >
                  <span>Save Connection</span>
                </button>

                <button
                  type="button"
                  className="primary-btn"
                  onClick={handleRunLiveScan}
                  disabled={testingConnection || scanning}
                >
                  {scanning ? <div className="spinner-small" /> : <Play size={16} />}
                  <span>Run Live Security Audit</span>
                </button>
              </div>
            </form>

            {/* Test Connection Result Box */}
            {connectionTestResult && (
              <div
                style={{
                  marginTop: '20px',
                  padding: '12px 16px',
                  borderRadius: '6px',
                  border: `1px solid ${connectionTestResult.success ? '#86efac' : '#fca5a5'}`,
                  backgroundColor: connectionTestResult.success ? '#f0fdf4' : '#fef2f2',
                  fontSize: '0.85rem',
                  color: connectionTestResult.success ? '#166534' : '#991b1b'
                }}
              >
                {connectionTestResult.success ? (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                      <CheckCircle2 size={16} color="#16a34a" />
                      <span>AssumeRole Verification Successful</span>
                    </div>
                    <div>Account ID: <strong>{connectionTestResult.account_id}</strong></div>
                    <div>Assumed ARN: <code>{connectionTestResult.arn}</code></div>
                    <div>Temporary Token Valid Until: {connectionTestResult.expiration ? new Date(connectionTestResult.expiration).toLocaleTimeString() : 'N/A'}</div>
                  </div>
                ) : (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                      <XCircle size={16} color="#dc2626" />
                      <span>Connection Verification Failed</span>
                    </div>
                    <div>{connectionTestResult.error || connectionTestResult.message}</div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* IAM Role Setup Guide */}
          <div className="content-card">
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '12px' }}>
              IAM Cross-Account Setup Guide
            </h3>

            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <p style={{ marginBottom: '12px' }}>
                CloudGuard requires read-only permissions to audit your infrastructure. Create an IAM Role in your AWS account with the following trust policy:
              </p>

              <div style={{ marginBottom: '12px' }}>
                <span style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Sample IAM Trust Policy:
                </span>
                <pre
                  style={{
                    backgroundColor: '#0f172a',
                    color: '#e2e8f0',
                    padding: '10px',
                    borderRadius: '6px',
                    fontSize: '0.75rem',
                    overflowX: 'auto',
                    marginTop: '4px'
                  }}
                >{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${connectionForm.account_id || '<YOUR-ACCOUNT-ID>'}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`}</pre>
              </div>

              <div>
                <span style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Recommended Attached Policy:
                </span>
                <div style={{ marginTop: '4px', padding: '8px 12px', backgroundColor: '#f1f5f9', borderRadius: '6px' }}>
                  <code>arn:aws:iam::aws:policy/SecurityAudit</code>
                </div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                  The AWS managed <code>SecurityAudit</code> policy grants read-only permissions to inspect S3, IAM, EC2, CloudTrail, and RDS configurations.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AUDIT HISTORY */}
      {activeTab === 'history' && (
        <div className="content-card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Cloud Infrastructure Audit History</h2>
              <p className="card-subtitle">Previous security assessments and score evolution</p>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '12px 10px' }}>Date & Time</th>
                  <th style={{ padding: '12px 10px' }}>Type</th>
                  <th style={{ padding: '12px 10px' }}>Account ID</th>
                  <th style={{ padding: '12px 10px' }}>Region</th>
                  <th style={{ padding: '12px 10px' }}>Security Score</th>
                  <th style={{ padding: '12px 10px' }}>Findings Breakdown</th>
                  <th style={{ padding: '12px 10px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {historyList.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                      No cloud security assessments recorded yet. Run a simulation or live scan.
                    </td>
                  </tr>
                ) : (
                  historyList.map((h) => (
                    <tr key={h.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '10px' }}>
                        {h.created_at ? new Date(h.created_at).toLocaleString() : 'N/A'}
                      </td>
                      <td style={{ padding: '10px' }}>
                        {h.is_simulation ? (
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, backgroundColor: '#fef3c7', color: '#92400e', padding: '2px 8px', borderRadius: '4px' }}>
                            Simulated Demo
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, backgroundColor: '#dcfce7', color: '#166534', padding: '2px 8px', borderRadius: '4px' }}>
                            Live AWS
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '10px' }}>
                        <code>{h.account_id}</code>
                      </td>
                      <td style={{ padding: '10px', color: 'var(--text-muted)' }}>
                        {h.region}
                      </td>
                      <td style={{ padding: '10px' }}>
                        <ScoreGauge score={h.security_score} size="small" />
                      </td>
                      <td style={{ padding: '10px' }}>
                        <span style={{ color: '#dc2626', fontWeight: 600 }}>{h.critical_count} Crit</span> •{' '}
                        <span style={{ color: '#ea580c' }}>{h.high_count} High</span> •{' '}
                        <span style={{ color: '#d97706' }}>{h.medium_count} Med</span> •{' '}
                        <span style={{ color: '#16a34a' }}>{h.checks_passed} Pass</span>
                      </td>
                      <td style={{ padding: '10px', textAlign: 'right' }}>
                        <button
                          className="link-btn"
                          onClick={() => handleSelectHistoryScan(h.id)}
                        >
                          View Results
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* FINDING DETAILS MODAL */}
      {selectedFinding && (
        <div
          className="modal-backdrop"
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="modal-content"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderRadius: '12px',
              maxWidth: '720px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '28px',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <SeverityBadge severity={selectedFinding.severity} />
                  <StatusBadge status={selectedFinding.status} />
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#3b82f6', backgroundColor: '#eff6ff', padding: '2px 8px', borderRadius: '4px' }}>
                    {selectedFinding.service}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Region: {selectedFinding.region || currentAssessment?.region}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedFinding.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Affected Resource */}
            <div style={{ marginBottom: '16px', padding: '10px 14px', backgroundColor: '#f8fafc', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>AFFECTED RESOURCE</div>
              <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)', marginTop: '2px' }}>
                <code>{selectedFinding.resource_id}</code>
              </div>
            </div>

            {/* Explanation & Risk */}
            <div style={{ marginBottom: '18px' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                Finding Explanation
              </h4>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                {selectedFinding.description}
              </p>
            </div>

            {/* Why This is a Security Risk */}
            {selectedFinding.remediation_details?.risk_explanation && (
              <div style={{ marginBottom: '18px', padding: '12px 16px', backgroundColor: '#fef2f2', borderRadius: '6px', borderLeft: '4px solid #dc2626' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, color: '#991b1b', fontSize: '0.85rem', marginBottom: '4px' }}>
                  <ShieldAlert size={16} />
                  <span>Why This is a Security Risk</span>
                </div>
                <p style={{ fontSize: '0.85rem', color: '#7f1d1d', lineHeight: 1.5 }}>
                  {selectedFinding.remediation_details.risk_explanation}
                </p>
              </div>
            )}

            {/* Configuration Evidence */}
            {selectedFinding.evidence && (
              <div style={{ marginBottom: '18px' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Configuration Evidence (From AWS API)
                </h4>
                <pre
                  style={{
                    backgroundColor: '#1e293b',
                    color: '#e2e8f0',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap'
                  }}
                >
                  {selectedFinding.evidence}
                </pre>
              </div>
            )}

            {/* Remediation Guide */}
            <div style={{ marginBottom: '18px' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                Step-by-Step Remediation Instructions
              </h4>

              {selectedFinding.remediation_details?.console_steps ? (
                <div style={{ backgroundColor: '#f8fafc', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--border)', marginBottom: '12px' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px' }}>
                    AWS Management Console:
                  </div>
                  <ol style={{ paddingLeft: '18px', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    {selectedFinding.remediation_details.console_steps.map((step, idx) => (
                      <li key={idx} style={{ marginBottom: '4px' }}>{step}</li>
                    ))}
                  </ol>
                </div>
              ) : (
                <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '12px' }}>
                  {selectedFinding.remediation}
                </p>
              )}

              {/* AWS CLI Command */}
              {selectedFinding.remediation_details?.cli_command && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>
                      AWS CLI Remediation Command:
                    </span>
                    <button
                      className="link-btn"
                      onClick={() => copyToClipboard(selectedFinding.remediation_details.cli_command)}
                      style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.75rem' }}
                    >
                      {copiedCli ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                      <span>{copiedCli ? 'Copied' : 'Copy Command'}</span>
                    </button>
                  </div>
                  <pre
                    style={{
                      backgroundColor: '#0f172a',
                      color: '#38bdf8',
                      padding: '10px 14px',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap'
                    }}
                  >
                    {selectedFinding.remediation_details.cli_command}
                  </pre>
                </div>
              )}

              {/* Best practice callout */}
              {selectedFinding.remediation_details?.best_practice && (
                <div style={{ marginTop: '12px', fontSize: '0.8rem', color: '#0369a1', backgroundColor: '#e0f2fe', padding: '8px 12px', borderRadius: '6px' }}>
                  <strong>Best Practice:</strong> {selectedFinding.remediation_details.best_practice}
                </div>
              )}
            </div>

            {/* Modal Close Button */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '20px' }}>
              <button className="primary-btn" onClick={() => setSelectedFinding(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
