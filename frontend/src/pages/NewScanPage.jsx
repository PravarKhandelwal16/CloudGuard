import React, { useState, useRef } from 'react';
import { UploadCloud, FileArchive, AlertCircle, CheckCircle, ShieldCheck, Cpu } from 'lucide-react';
import { api } from '../api/client';

export function NewScanPage({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelected(e.target.files[0]);
    }
  };

  const handleFileSelected = (selectedFile) => {
    setError('');
    // Validation
    if (!selectedFile.name.toLowerCase().endsWith('.zip')) {
      setError('Invalid file type. Please select a .zip archive.');
      setFile(null);
      return;
    }

    const maxBytes = 25 * 1024 * 1024; // 25 MB
    if (selectedFile.size > maxBytes) {
      setError('File exceeds 25 MB limit. Please select a smaller archive.');
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const handleStartScan = async () => {
    if (!file) {
      setError('Please select a project ZIP file to scan.');
      return;
    }

    setError('');
    setScanning(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await api.uploadScan(formData);
      if (res.success && res.data) {
        onScanComplete(res.data.id);
      } else {
        throw new Error(res.message || 'Scan failed.');
      }
    } catch (err) {
      setError(err.message || 'Scan failed. Ensure the ZIP archive is valid and unencrypted.');
      setScanning(false);
    }
  };

  return (
    <div className="new-scan-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">New Secrets Scan</h1>
          <p className="page-desc">Upload a project ZIP archive to scan for leaked credentials</p>
        </div>
      </div>

      <div className="content-card upload-container">
        {error && (
          <div className="alert-box error" style={{ marginBottom: '20px' }}>
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {scanning ? (
          <div className="scanning-state">
            <div className="scanning-pulse">
              <Cpu size={48} color="#2563eb" />
            </div>
            <h2>Analyzing Project Archive</h2>
            <p className="scanning-text">
              Extracting source files safely, executing regex rule patterns, and evaluating candidates with the Random Forest ML model...
            </p>
            <div className="pipeline-steps">
              <div className="step-item active">
                <CheckCircle size={16} color="#16a34a" />
                <span>Safe ZIP decompression & entry limits verified</span>
              </div>
              <div className="step-item active">
                <CheckCircle size={16} color="#16a34a" />
                <span>Text file candidate extraction & Shannon entropy calculation</span>
              </div>
              <div className="step-item active">
                <Cpu size={16} color="#2563eb" />
                <span>Random Forest machine learning classifier evaluating candidate strings</span>
              </div>
              <div className="step-item">
                <ShieldCheck size={16} color="#64748b" />
                <span>Risk assessment, scoring, and masking</span>
              </div>
            </div>
          </div>
        ) : (
          <div>
            <div
              className={`dropzone ${dragActive ? 'drag-active' : ''} ${file ? 'has-file' : ''}`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                style={{ display: 'none' }}
                onChange={handleFileChange}
              />

              {file ? (
                <div className="file-preview">
                  <FileArchive size={48} color="#2563eb" />
                  <div className="file-name">{file.name}</div>
                  <div className="file-meta">
                    {(file.size / (1024 * 1024)).toFixed(2)} MB &bull; Ready to scan
                  </div>
                  <button
                    type="button"
                    className="secondary-btn"
                    style={{ marginTop: '12px' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setFile(null);
                    }}
                  >
                    Change File
                  </button>
                </div>
              ) : (
                <div className="dropzone-content">
                  <UploadCloud size={48} color="#64748b" />
                  <h3>Choose a project ZIP or drag & drop here</h3>
                  <p className="dropzone-hint">
                    Supports standard .zip archives up to 25 MB
                  </p>
                  <button type="button" className="secondary-btn" style={{ marginTop: '12px' }}>
                    Browse Files
                  </button>
                </div>
              )}
            </div>

            <div className="scan-guarantees">
              <div className="guarantee-item">
                <strong>Safe Inspection:</strong> Uploaded source code is never built, executed, or imported.
              </div>
              <div className="guarantee-item">
                <strong>Masked Evidence:</strong> Plaintext secrets are never stored, logged, or returned in API responses.
              </div>
              <div className="guarantee-item">
                <strong>Hybrid Detection:</strong> Combines rule-based detection patterns with trained scikit-learn Random Forest ML inference.
              </div>
            </div>

            <div className="upload-actions">
              <button
                type="button"
                className="primary-btn"
                disabled={!file}
                onClick={handleStartScan}
                style={{ padding: '12px 28px', fontSize: '1rem' }}
              >
                <ShieldCheck size={20} />
                <span>Start Scan</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

