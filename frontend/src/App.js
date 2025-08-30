import React, { useState, useEffect } from 'react';
import './App.css';
import axios from 'axios';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const COLORS = {
  high: '#ef4444',
  medium: '#f97316', 
  low: '#3b82f6',
  info: '#6b7280'
};

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [results, setResults] = useState([]);
  const [modules, setModules] = useState([]);
  const [scanPresets, setScanPresets] = useState({});
  const [ws, setWs] = useState(null);
  const [realtimeUpdates, setRealtimeUpdates] = useState({});

  // WebSocket connection for real-time updates
  useEffect(() => {
    const wsUrl = BACKEND_URL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws';
    const websocket = new WebSocket(wsUrl);
    
    websocket.onopen = () => {
      console.log('WebSocket connected');
      setWs(websocket);
    };
    
    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('WebSocket message:', data);
      
      if (data.type === 'scan_progress') {
        setRealtimeUpdates(prev => ({
          ...prev,
          [data.result_id]: {
            progress: data.progress,
            phase: data.phase,
            message: data.message
          }
        }));
      }
      
      if (data.type === 'scan_completed' || data.type === 'scan_error' || data.type === 'scan_progress') {
        fetchResults();
      }
    };
    
    websocket.onclose = () => {
      console.log('WebSocket disconnected');
      setWs(null);
    };
    
    return () => {
      if (websocket.readyState === WebSocket.OPEN) {
        websocket.close();
      }
    };
  }, []);

  // Fetch data
  useEffect(() => {
    fetchScans();
    fetchResults();
    fetchModules();
    fetchScanPresets();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API}/scans`);
      setScans(response.data);
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const fetchResults = async () => {
    try {
      const response = await axios.get(`${API}/results`);
      setResults(response.data);
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  };

  const fetchModules = async () => {
    try {
      const response = await axios.get(`${API}/modules`);
      setModules(response.data.modules);
    } catch (error) {
      console.error('Error fetching modules:', error);
    }
  };

  const fetchScanPresets = async () => {
    try {
      const response = await axios.get(`${API}/scan-presets`);
      setScanPresets(response.data.presets);
    } catch (error) {
      console.error('Error fetching scan presets:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800">
      {/* Header */}
      <header className="bg-black/20 backdrop-blur-sm border-b border-red-500/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="w-12 h-12 bg-gradient-to-r from-red-500 to-orange-500 rounded-lg flex items-center justify-center shadow-lg">
                  <span className="text-white font-bold text-xl">S</span>
                </div>
                <div>
                  <h1 className="text-3xl font-bold text-white">SPAWN</h1>
                  <p className="text-gray-400 text-sm">Professional Vulnerability Scanner</p>
                </div>
              </div>
            </div>
            
            <nav className="flex space-x-8">
              {['dashboard', 'scans', 'results', 'create'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-6 py-3 rounded-lg font-medium transition-all ${
                    activeTab === tab
                      ? 'bg-gradient-to-r from-red-500 to-orange-500 text-white shadow-lg transform scale-105'
                      : 'text-gray-300 hover:text-white hover:bg-red-500/20'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && <Dashboard results={results} />}
        {activeTab === 'scans' && <ScanList scans={scans} onRefresh={fetchScans} />}
        {activeTab === 'results' && <ResultsList results={results} onRefresh={fetchResults} />}
        {activeTab === 'create' && <CreateScan modules={modules} scanPresets={scanPresets} onCreated={fetchScans} />}
      </main>
    </div>
  );
};

const Dashboard = ({ results }) => {
  const totalScans = results.length;
  const completedScans = results.filter(r => r.status === 'completed').length;
  const runningScans = results.filter(r => r.status === 'running').length;
  const failedScans = results.filter(r => r.status === 'failed').length;
  
  const allVulns = results.reduce((acc, r) => acc.concat(r.vulnerabilities || []), []);
  const totalVulns = allVulns.length;
  
  const vulnBySeverity = {
    high: allVulns.filter(v => v.severity === 'high').length,
    medium: allVulns.filter(v => v.severity === 'medium').length,
    low: allVulns.filter(v => v.severity === 'low').length,
    info: allVulns.filter(v => v.severity === 'info').length
  };

  // Prepare pie chart data
  const pieData = Object.entries(vulnBySeverity)
    .filter(([_, count]) => count > 0)
    .map(([severity, count]) => ({
      name: severity.toUpperCase(),
      value: count,
      color: COLORS[severity]
    }));

  // Prepare scan status data
  const scanStatusData = [
    { name: 'Completed', value: completedScans, color: '#10b981' },
    { name: 'Running', value: runningScans, color: '#f59e0b' },
    { name: 'Failed', value: failedScans, color: '#ef4444' }
  ].filter(item => item.value > 0);

  // Recent activity data for trend
  const recentActivity = results
    .filter(r => r.started_at)
    .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
    .slice(0, 7)
    .map(r => ({
      date: new Date(r.started_at).toLocaleDateString(),
      vulnerabilities: (r.vulnerabilities || []).length,
      high: (r.vulnerabilities || []).filter(v => v.severity === 'high').length
    }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-800 border border-gray-600 rounded-lg p-3 shadow-lg">
          <p className="text-white font-medium">{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-4xl font-bold text-white mb-2">Security Dashboard</h2>
        <p className="text-gray-400 text-lg">Comprehensive overview of your vulnerability scanning activities</p>
      </div>

      {/* Key Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="Total Scans" value={totalScans} icon="🔍" color="blue" />
        <StatCard title="Completed" value={completedScans} icon="✅" color="green" />
        <StatCard title="Active Scans" value={runningScans} icon="⚡" color="yellow" />
        <StatCard title="Total Vulnerabilities" value={totalVulns} icon="⚠️" color="red" />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Vulnerability Severity Distribution */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6">
          <h3 className="text-xl font-semibold text-white mb-4">Vulnerability Severity Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                  label={({name, value}) => `${name}: ${value}`}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px]">
              <p className="text-gray-400 text-lg">No vulnerability data available</p>
            </div>
          )}
        </div>

        {/* Scan Status Distribution */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6">
          <h3 className="text-xl font-semibold text-white mb-4">Scan Status Distribution</h3>
          {scanStatusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={scanStatusData}
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                  label={({name, value}) => `${name}: ${value}`}
                >
                  {scanStatusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px]">
              <p className="text-gray-400 text-lg">No scan data available</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity Trend */}
      {recentActivity.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6">
          <h3 className="text-xl font-semibold text-white mb-4">Recent Activity Trend</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={recentActivity}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="date" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #4b5563', borderRadius: '8px' }}
                labelStyle={{ color: '#f9fafb' }}
              />
              <Legend />
              <Bar dataKey="vulnerabilities" fill="#3b82f6" name="Total Vulnerabilities" />
              <Bar dataKey="high" fill="#ef4444" name="High Severity" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Scan Activity */}
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Recent Scan Activity</h3>
        <div className="space-y-4">
          {results.slice(0, 5).map((result, index) => (
            <div key={index} className="flex items-center justify-between p-4 bg-gray-700/30 rounded-lg hover:bg-gray-700/50 transition-colors">
              <div className="flex items-center space-x-4">
                <StatusBadge status={result.status} />
                <div>
                  <p className="text-white font-medium">{result.scan_name || 'Unknown Scan'}</p>
                  <p className="text-gray-400 text-sm">{result.target_url}</p>
                </div>
              </div>
              <div className="text-right">
                <div className="flex space-x-4 text-sm">
                  {result.vulnerabilities && (
                    <>
                      <span className="text-red-400">H: {result.vulnerabilities.filter(v => v.severity === 'high').length}</span>
                      <span className="text-orange-400">M: {result.vulnerabilities.filter(v => v.severity === 'medium').length}</span>
                      <span className="text-blue-400">L: {result.vulnerabilities.filter(v => v.severity === 'low').length}</span>
                    </>
                  )}
                </div>
                <p className="text-gray-500 text-sm">
                  {new Date(result.started_at).toLocaleDateString()}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ title, value, icon, color }) => {
  const colorClasses = {
    blue: 'from-blue-500 to-blue-600',
    green: 'from-green-500 to-green-600', 
    yellow: 'from-yellow-500 to-yellow-600',
    red: 'from-red-500 to-red-600'
  };

  return (
    <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6 hover:bg-gray-800/70 transition-colors">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-2">{value}</p>
        </div>
        <div className={`w-14 h-14 bg-gradient-to-r ${colorClasses[color]} rounded-lg flex items-center justify-center text-2xl shadow-lg`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

const StatusBadge = ({ status }) => {
  const statusStyles = {
    running: 'bg-blue-500 text-white animate-pulse',
    completed: 'bg-green-500 text-white',
    failed: 'bg-red-500 text-white',
    stopped: 'bg-gray-500 text-white'
  };

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusStyles[status] || statusStyles.stopped}`}>
      {status?.toUpperCase() || 'UNKNOWN'}
    </span>
  );
};

const ProgressBar = ({ progress, status }) => {
  return (
    <div className="w-full bg-gray-700 rounded-full h-2">
      <div 
        className={`h-2 rounded-full transition-all duration-500 ${
          status === 'completed' ? 'bg-green-500' : 
          status === 'failed' ? 'bg-red-500' : 
          'bg-blue-500'
        }`}
        style={{ width: `${progress}%` }}
      />
    </div>
  );
};

const ScanList = ({ scans, onRefresh }) => {
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanProgress, setScanProgress] = useState({});

  const startScan = async (scanId) => {
    try {
      await axios.post(`${API}/scans/${scanId}/start`);
      alert('Scan started successfully!');
      onRefresh();
    } catch (error) {
      alert('Error starting scan: ' + error.response?.data?.detail);
    }
  };

  const stopScan = async (scanId) => {
    try {
      await axios.post(`${API}/scans/${scanId}/stop`);
      alert('Scan stopped successfully!');
      onRefresh();
    } catch (error) {
      alert('Error stopping scan: ' + error.response?.data?.detail);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-4xl font-bold text-white mb-2">Scan Configurations</h2>
        <p className="text-gray-400 text-lg">Manage your vulnerability scan configurations</p>
      </div>

      <div className="grid gap-6">
        {scans.map((scan) => (
          <div key={scan.id} className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6 hover:bg-gray-800/70 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-xl font-semibold text-white">{scan.name}</h3>
                  <span className="px-3 py-1 bg-gradient-to-r from-red-500 to-orange-500 text-white text-xs font-medium rounded-full">
                    {scan.scan_type?.toUpperCase() || 'STANDARD'}
                  </span>
                </div>
                <p className="text-gray-400">{scan.target_url}</p>
                {scanProgress[scan.id] && (
                  <div className="mt-3">
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-sm text-gray-300">Progress</span>
                      <span className="text-sm text-gray-300">{scanProgress[scan.id]}%</span>
                    </div>
                    <ProgressBar progress={scanProgress[scan.id]} status="running" />
                  </div>
                )}
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => startScan(scan.id)}
                  className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors font-medium"
                >
                  Start Scan
                </button>
                <button
                  onClick={() => stopScan(scan.id)}
                  className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors font-medium"
                >
                  Stop Scan
                </button>
                <button
                  onClick={() => setSelectedScan(selectedScan === scan.id ? null : scan.id)}
                  className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors font-medium"
                >
                  {selectedScan === scan.id ? 'Hide Details' : 'View Details'}
                </button>
              </div>
            </div>
            
            {selectedScan === scan.id && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 p-4 bg-gray-700/30 rounded-lg">
                <div>
                  <p className="text-gray-400 text-sm">Scope</p>
                  <p className="text-white font-medium">{scan.scope}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Depth</p>
                  <p className="text-white font-medium">{scan.depth}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Level</p>
                  <p className="text-white font-medium">{scan.level}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Timeout</p>
                  <p className="text-white font-medium">{scan.timeout}s</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Created</p>
                  <p className="text-white font-medium">{new Date(scan.created_at).toLocaleString()}</p>
                </div>
                <div className="md:col-span-3">
                  <p className="text-gray-400 text-sm">Modules</p>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {(scan.modules || []).map(module => (
                      <span key={module} className="px-2 py-1 bg-gray-600 text-white text-xs rounded">
                        {module}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

const ResultsList = ({ results, onRefresh }) => {
  const [selectedResult, setSelectedResult] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);

  const exportResult = async (resultId, format) => {
    try {
      const response = await axios.get(`${API}/results/${resultId}/export/${format}`, {
        responseType: format === 'json' ? 'json' : 'blob'
      });
      
      if (format === 'json') {
        console.log('JSON Export:', response.data);
        return;
      }
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `SPAWN_Security_Report_${resultId}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      alert('Error exporting result: ' + error.message);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-4xl font-bold text-white mb-2">Scan Results</h2>
        <p className="text-gray-400 text-lg">View and export your vulnerability scan results</p>
      </div>

      <div className="grid gap-6">
        {results.map((result) => (
          <div key={result.id} className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6 hover:bg-gray-800/70 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <div className="flex-1">
                <h3 className="text-xl font-semibold text-white">{result.scan_name || 'Unknown Scan'}</h3>
                <p className="text-gray-400">{result.target_url}</p>
                <div className="flex items-center space-x-4 mt-2">
                  <StatusBadge status={result.status} />
                  <span className="text-gray-300">{result.vulnerabilities?.length || 0} vulnerabilities found</span>
                  {result.progress !== undefined && result.status === 'running' && (
                    <div className="flex items-center space-x-2">
                      <span className="text-blue-400 text-sm">{result.progress}%</span>
                      <ProgressBar progress={result.progress} status={result.status} />
                    </div>
                  )}
                </div>
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => exportResult(result.id, 'pdf')}
                  className="px-3 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors text-sm font-medium"
                >
                  PDF
                </button>
                <button
                  onClick={() => exportResult(result.id, 'csv')}
                  className="px-3 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors text-sm font-medium"
                >
                  CSV
                </button>
                <button
                  onClick={() => exportResult(result.id, 'html')}
                  className="px-3 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm font-medium"
                >
                  HTML
                </button>
                <button
                  onClick={() => setSelectedResult(selectedResult === result.id ? null : result.id)}
                  className="px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg transition-colors font-medium"
                >
                  {selectedResult === result.id ? 'Hide' : 'View'}
                </button>
              </div>
            </div>

            {selectedResult === result.id && result.vulnerabilities && (
              <div className="mt-4 space-y-4">
                <h4 className="text-lg font-semibold text-white">Vulnerabilities</h4>
                {result.vulnerabilities.map((vuln, index) => (
                  <div key={index} className="bg-gray-700/30 rounded-lg p-4 hover:bg-gray-700/50 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <SeverityBadge severity={vuln.severity} />
                        <div>
                          <p className="text-white font-medium">{vuln.title}</p>
                          <p className="text-gray-400 text-sm">{vuln.module} - {vuln.url}</p>
                        </div>
                      </div>
                      <button
                        onClick={() => setSelectedVuln(selectedVuln === index ? null : index)}
                        className="px-3 py-1 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm font-medium"
                      >
                        {selectedVuln === index ? 'Less' : 'More'}
                      </button>
                    </div>
                    
                    {selectedVuln === index && (
                      <div className="mt-4 p-4 bg-gray-600/30 rounded-lg">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-gray-400 text-sm">Parameter</p>
                            <p className="text-white">{vuln.parameter || 'N/A'}</p>
                          </div>
                          <div>
                            <p className="text-gray-400 text-sm">Method</p>
                            <p className="text-white">{vuln.method}</p>
                          </div>
                        </div>
                        <div className="mt-4">
                          <p className="text-gray-400 text-sm">Description</p>
                          <p className="text-white">{vuln.description}</p>
                        </div>
                        {vuln.attack_payload && (
                          <div className="mt-4">
                            <p className="text-gray-400 text-sm">Attack Payload</p>
                            <pre className="text-green-400 bg-black/50 p-2 rounded mt-1 text-sm overflow-x-auto">
                              {vuln.attack_payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

const SeverityBadge = ({ severity }) => {
  const severityStyles = {
    high: 'bg-red-500 text-white',
    medium: 'bg-orange-500 text-white',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-500 text-white'
  };

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-bold ${severityStyles[severity] || severityStyles.info}`}>
      {severity?.toUpperCase() || 'INFO'}
    </span>
  );
};

const CreateScan = ({ modules, scanPresets, onCreated }) => {
  const [formData, setFormData] = useState({
    name: '',
    target_url: '',
    scan_type: 'standard',
    scope: 'folder',
    modules: ['exec', 'file', 'sql', 'xss', 'csrf', 'ssrf'],
    depth: 5,
    level: 1,
    timeout: 30,
    verify_ssl: true
  });

  const handleScanTypeChange = (scanType) => {
    const preset = scanPresets[scanType];
    if (preset) {
      setFormData(prev => ({
        ...prev,
        scan_type: scanType,
        modules: preset.modules,
        depth: preset.depth,
        level: preset.level,
        timeout: preset.timeout
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/scans`, formData);
      alert('Scan configuration created successfully!');
      onCreated();
      setFormData({
        name: '',
        target_url: '',
        scan_type: 'standard',
        scope: 'folder',
        modules: ['exec', 'file', 'sql', 'xss', 'csrf', 'ssrf'],
        depth: 5,
        level: 1,
        timeout: 30,
        verify_ssl: true
      });
    } catch (error) {
      alert('Error creating scan: ' + error.response?.data?.detail);
    }
  };

  const handleModuleToggle = (module) => {
    setFormData(prev => ({
      ...prev,
      modules: prev.modules.includes(module)
        ? prev.modules.filter(m => m !== module)
        : [...prev.modules, module]
    }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-4xl font-bold text-white mb-2">Create New Scan</h2>
        <p className="text-gray-400 text-lg">Configure a new vulnerability scan with advanced options</p>
      </div>

      <form onSubmit={handleSubmit} className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700/50 p-6 space-y-6">
        {/* Scan Type Selection */}
        <div>
          <label className="block text-gray-300 text-sm font-medium mb-4">Scan Type</label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(scanPresets).map(([type, preset]) => (
              <div 
                key={type}
                onClick={() => handleScanTypeChange(type)}
                className={`p-4 border-2 rounded-lg cursor-pointer transition-colors ${
                  formData.scan_type === type 
                    ? 'border-red-500 bg-red-500/20' 
                    : 'border-gray-600 hover:border-gray-500'
                }`}
              >
                <div className="flex items-center space-x-2 mb-2">
                  <input
                    type="radio"
                    id={type}
                    name="scan_type"
                    value={type}
                    checked={formData.scan_type === type}
                    onChange={() => handleScanTypeChange(type)}
                    className="text-red-500"
                  />
                  <label htmlFor={type} className="text-white font-semibold capitalize cursor-pointer">
                    {type} Scan
                  </label>
                </div>
                <p className="text-gray-400 text-sm">{preset.description}</p>
                <div className="mt-2 text-xs text-gray-500">
                  <p>Modules: {preset.modules.length}</p>
                  <p>Depth: {preset.depth} | Level: {preset.level}</p>
                  <p>Timeout: {preset.timeout}s</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Scan Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              placeholder="Enter scan name"
              required
            />
          </div>
          
          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Target URL</label>
            <input
              type="url"
              value={formData.target_url}
              onChange={(e) => setFormData(prev => ({ ...prev, target_url: e.target.value }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              placeholder="https://example.com"
              required
            />
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Scope</label>
            <select
              value={formData.scope}
              onChange={(e) => setFormData(prev => ({ ...prev, scope: e.target.value }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
            >
              <option value="url">URL</option>
              <option value="page">Page</option>
              <option value="folder">Folder</option>
              <option value="subdomain">Subdomain</option>
              <option value="domain">Domain</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Depth</label>
            <input
              type="number"
              value={formData.depth}
              onChange={(e) => setFormData(prev => ({ ...prev, depth: parseInt(e.target.value) }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              min="1"
              max="10"
            />
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Attack Level</label>
            <select
              value={formData.level}
              onChange={(e) => setFormData(prev => ({ ...prev, level: parseInt(e.target.value) }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
            >
              <option value="1">Level 1 - Basic</option>
              <option value="2">Level 2 - Advanced</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">Timeout (seconds)</label>
            <input
              type="number"
              value={formData.timeout}
              onChange={(e) => setFormData(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              min="10"
              max="300"
            />
          </div>
        </div>

        <div>
          <label className="block text-gray-300 text-sm font-medium mb-4">Scan Modules ({formData.modules.length} selected)</label>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {modules.map(module => (
              <div key={module} className="flex items-center">
                <input
                  type="checkbox"
                  id={module}
                  checked={formData.modules.includes(module)}
                  onChange={() => handleModuleToggle(module)}
                  className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500"
                />
                <label htmlFor={module} className="ml-2 text-gray-300 text-sm">
                  {module}
                </label>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center">
          <input
            type="checkbox"
            id="verify_ssl"
            checked={formData.verify_ssl}
            onChange={(e) => setFormData(prev => ({ ...prev, verify_ssl: e.target.checked }))}
            className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500"
          />
          <label htmlFor="verify_ssl" className="ml-2 text-gray-300">
            Verify SSL certificates
          </label>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="px-8 py-3 bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-600 hover:to-orange-600 text-white font-medium rounded-lg transition-all transform hover:scale-105 shadow-lg"
          >
            Create Scan Configuration
          </button>
        </div>
      </form>
    </div>
  );
};

export default App;