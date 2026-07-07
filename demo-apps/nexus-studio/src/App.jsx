import { useState, useCallback, useEffect, useRef } from 'react';

// ============================================================
// SAMPLE DATA
// ============================================================
const SAMPLE_JSON = JSON.stringify({
  project: "Nexus Studio",
  version: "1.0.0",
  config: {
    theme: "dark",
    language: "en",
    features: {
      formatting: true,
      validation: true,
      diffing: true,
      statistics: true,
    },
  },
  team: [
    { name: "Alice", role: "Lead Engineer", skills: ["React", "Node.js", "TypeScript"] },
    { name: "Bob", role: "Designer", skills: ["Figma", "CSS", "Motion"] },
    { name: "Charlie", role: "DevOps", skills: ["Docker", "K8s", "Terraform"] },
  ],
  metadata: {
    createdAt: "2024-01-15T09:30:00Z",
    buildNumber: 2847,
    isProduction: false,
    tags: ["beta", "internal", "v2"],
  },
}, null, 2);

// ============================================================
// JSON SYNTAX HIGHLIGHTER
// ============================================================
function highlightJson(json) {
  if (!json) return '';
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(
      /("(?:\\.|[^"\\])*")\s*:/g,
      '<span class="json-key">$1</span><span class="json-colon">:</span>'
    )
    .replace(
      /:\s*("(?:\\.|[^"\\])*")/g,
      ': <span class="json-string">$1</span>'
    )
    .replace(
      /:\s*(-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g,
      ': <span class="json-number">$1</span>'
    )
    .replace(
      /:\s*(true|false)/g,
      ': <span class="json-boolean">$1</span>'
    )
    .replace(
      /:\s*(null)/g,
      ': <span class="json-null">$1</span>'
    )
    .replace(
      /([[\]{}])/g,
      '<span class="json-bracket">$1</span>'
    );
}

// ============================================================
// TOAST COMPONENT
// ============================================================
function Toast({ message, type, onClose }) {
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setExiting(true);
      setTimeout(onClose, 250);
    }, 2500);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`toast toast--${type} ${exiting ? 'toast-exit' : ''}`}>
      <span>{type === 'success' ? '\u2713' : '\u2717'}</span>
      {message}
    </div>
  );
}

// ============================================================
// MAIN APP COMPONENT
// ============================================================
export default function App() {
  const [input, setInput] = useState(SAMPLE_JSON);
  const [output, setOutput] = useState('');
  const [validation, setValidation] = useState({ status: 'valid', error: null });
  const [stats, setStats] = useState(null);
  const [toast, setToast] = useState(null);
  const [inputFocused, setInputFocused] = useState(false);
  const [sortKeys, setSortKeys] = useState(false);
  const [indent, setIndent] = useState(2);
  const editorRef = useRef(null);

  // Validate on input change
  useEffect(() => {
    if (!input.trim()) {
      setValidation({ status: 'empty', error: null });
      setStats(null);
      return;
    }
    try {
      const parsed = JSON.parse(input);
      setValidation({ status: 'valid', error: null });
      // Compute stats
      const computeStats = (obj) => {
        let keys = 0, arrays = 0, objects = 0, maxDepth = 0;
        const walk = (node, depth) => {
          if (depth > maxDepth) maxDepth = depth;
          if (Array.isArray(node)) { arrays++; node.forEach(i => walk(i, depth + 1)); }
          else if (node && typeof node === 'object') { objects++; const e = Object.entries(node); keys += e.length; e.forEach(([, v]) => walk(v, depth + 1)); }
        };
        walk(obj, 0);
        return { keys, arrays, objects, depth: maxDepth, size: JSON.stringify(obj).length };
      };
      setStats(computeStats(parsed));
    } catch (e) {
      setValidation({ status: 'invalid', error: e.message });
      setStats(null);
    }
  }, [input]);

  // Format JSON
  const handleFormat = useCallback(() => {
    try {
      let parsed = JSON.parse(input);
      if (sortKeys) {
        const deepSort = (obj) => {
          if (Array.isArray(obj)) return obj.map(deepSort);
          if (obj && typeof obj === 'object') {
            return Object.keys(obj).sort().reduce((acc, key) => {
              acc[key] = deepSort(obj[key]);
              return acc;
            }, {});
          }
          return obj;
        };
        parsed = deepSort(parsed);
      }
      const formatted = JSON.stringify(parsed, null, indent);
      setOutput(formatted);
      showToast('Formatted successfully', 'success');
    } catch (e) {
      showToast(`Error: ${e.message}`, 'error');
    }
  }, [input, sortKeys, indent]);

  // Minify JSON
  const handleMinify = useCallback(() => {
    try {
      const parsed = JSON.parse(input);
      setOutput(JSON.stringify(parsed));
      showToast('Minified successfully', 'success');
    } catch (e) {
      showToast(`Error: ${e.message}`, 'error');
    }
  }, [input]);

  // Copy output
  const handleCopy = useCallback(async () => {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output);
      showToast('Copied to clipboard', 'success');
    } catch {
      showToast('Failed to copy', 'error');
    }
  }, [output]);

  // Clear
  const handleClear = useCallback(() => {
    setInput('');
    setOutput('');
    setStats(null);
    editorRef.current?.focus();
  }, []);

  // Load sample
  const handleLoadSample = useCallback(() => {
    setInput(SAMPLE_JSON);
    setOutput('');
    editorRef.current?.focus();
  }, []);

  // Toast helper
  const showToast = (message, type) => {
    setToast({ message, type, id: Date.now() });
  };

  // Format on initial load
  useEffect(() => {
    handleFormat();
  }, []);

  return (
    <div className="app-wrapper">
      {/* Ambient background */}
      <div className="ambient-bg" aria-hidden="true">
        <div className="ambient-orb ambient-orb--1" />
        <div className="ambient-orb ambient-orb--2" />
        <div className="ambient-orb ambient-orb--3" />
      </div>

      {/* Header */}
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">N</div>
            <span className="logo-text">Nexus Studio</span>
          </div>
          <span className="header-badge">v1.0 Beta</span>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-content">
        {/* Hero */}
        <section className="hero">
          <h1 className="hero-title">
            <span className="gradient-text">JSON Visualization</span>
            <br />& Formatting Studio
          </h1>
          <p className="hero-subtitle">
            A premium toolkit for formatting, validating, and analyzing structured data.
            Powered by <strong>nexus-formatter</strong>.
          </p>
        </section>

        {/* Stats */}
        {stats && (
          <div className="stats-row">
            <div className="stat-card">
              <div className="stat-value">{stats.keys}</div>
              <div className="stat-label">Keys</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.depth}</div>
              <div className="stat-label">Depth</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.objects}</div>
              <div className="stat-label">Objects</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.arrays}</div>
              <div className="stat-label">Arrays</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{(stats.size / 1024).toFixed(1)}K</div>
              <div className="stat-label">Size</div>
            </div>
          </div>
        )}

        {/* Editor Layout */}
        <div className="editor-layout">
          {/* Input Panel */}
          <div className={`glass-panel ${inputFocused ? 'glass-panel--focused' : ''}`}>
            <div className="panel-header">
              <div className="panel-header-left">
                <span className="panel-dot panel-dot--green" />
                <span className="panel-dot panel-dot--orange" />
                <span className="panel-dot panel-dot--red" />
                <span className="panel-title">Input</span>
              </div>
              <div className="panel-actions">
                <button className="panel-action-btn" onClick={handleLoadSample}>Sample</button>
                <button className="panel-action-btn" onClick={handleClear}>Clear</button>
              </div>
            </div>
            <textarea
              ref={editorRef}
              id="json-input"
              className="code-editor"
              value={input}
              onChange={e => setInput(e.target.value)}
              onFocus={() => setInputFocused(true)}
              onBlur={() => setInputFocused(false)}
              placeholder='Paste your JSON here...'
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
            />
            <div className="validation-bar">
              <div className={`validation-badge validation-badge--${validation.status}`}>
                <span className="validation-badge-dot" />
                {validation.status === 'valid' ? 'Valid JSON' : validation.status === 'invalid' ? 'Invalid' : 'Empty'}
              </div>
              <span className="char-count">{input.length.toLocaleString()} chars</span>
            </div>
          </div>

          {/* Output Panel */}
          <div className="glass-panel">
            <div className="panel-header">
              <div className="panel-header-left">
                <span className="panel-dot panel-dot--green" />
                <span className="panel-dot panel-dot--orange" />
                <span className="panel-dot panel-dot--red" />
                <span className="panel-title">Output</span>
              </div>
              <div className="panel-actions">
                <button className="panel-action-btn" onClick={handleCopy}>Copy</button>
              </div>
            </div>
            <div
              id="json-output"
              className="code-output"
              dangerouslySetInnerHTML={{ __html: highlightJson(output) || '<span style="color: var(--text-muted)">Formatted output will appear here...</span>' }}
            />
            <div className="validation-bar">
              <div className={`validation-badge validation-badge--${output ? 'valid' : 'empty'}`}>
                <span className="validation-badge-dot" />
                {output ? 'Ready' : 'Waiting'}
              </div>
              <span className="char-count">{output.length.toLocaleString()} chars</span>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="toolbar">
          <button id="btn-format" className="btn btn--primary" onClick={handleFormat}>
            Format JSON
          </button>
          <button id="btn-minify" className="btn btn--secondary" onClick={handleMinify}>
            Minify
          </button>
          <button id="btn-copy" className="btn btn--secondary" onClick={handleCopy}>
            Copy Output
          </button>
          <button id="btn-clear" className="btn btn--danger" onClick={handleClear}>
            Clear All
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={sortKeys}
              onChange={e => setSortKeys(e.target.checked)}
              style={{ accentColor: 'var(--accent-primary)' }}
            />
            Sort Keys
          </label>
          <select
            value={indent}
            onChange={e => setIndent(Number(e.target.value))}
            style={{
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid var(--glass-border)',
              color: 'var(--text-secondary)',
              padding: '0.4rem 0.7rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8rem',
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value={2}>2 spaces</option>
            <option value={4}>4 spaces</option>
            <option value={8}>8 spaces</option>
          </select>
        </div>

        {/* Features Section */}
        <section className="features-section">
          <div className="features-title">Powered by nexus-formatter</div>
          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">{'\u2728'}</div>
              <div className="feature-name">Smart Formatting</div>
              <div className="feature-desc">Intelligent pretty-printing with configurable indentation and key sorting.</div>
            </div>
            <div className="feature-card">
              <div className="feature-icon">{'\u2705'}</div>
              <div className="feature-name">Real-time Validation</div>
              <div className="feature-desc">Instant feedback on JSON validity with detailed error messages.</div>
            </div>
            <div className="feature-card">
              <div className="feature-icon">{'\u{1F4CA}'}</div>
              <div className="feature-name">Structure Analysis</div>
              <div className="feature-desc">Live statistics: key count, nesting depth, object/array counts, and payload size.</div>
            </div>
            <div className="feature-card">
              <div className="feature-icon">{'\u26A1'}</div>
              <div className="feature-name">Minification</div>
              <div className="feature-desc">One-click minification for production-ready compact JSON output.</div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p className="footer-text">
          Nexus Studio &mdash; Built with React & nexus-formatter v2.1.0
        </p>
      </footer>

      {/* Toast Notifications */}
      {toast && <Toast key={toast.id} message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
