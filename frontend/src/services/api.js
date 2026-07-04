import axios from 'axios';
import { getCookie } from '../utils/cookies';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

// Create axios instance for direct API calls
const apiClient = axios.create({
  baseURL: API,
  headers: {
    'Content-Type': 'application/json',
  },
});

const getHeaders = () => {
  const token = getCookie('auth_token');
  return {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` })
  };
};

export const api = {
  // Repositories
  getRepositories: async () => {
    const response = await axios.get(`${API}/repositories`, { headers: getHeaders() });
    return response.data;
  },
  
  getRepository: async (id) => {
    const response = await axios.get(`${API}/repositories/${id}`, { headers: getHeaders() });
    return response.data;
  },
  
  createRepository: async (data) => {
    const response = await axios.post(`${API}/repositories`, data, { headers: getHeaders() });
    return response.data;
  },
  
  deleteRepository: async (id) => {
    await axios.delete(`${API}/repositories/${id}`, { headers: getHeaders() });
  },
  
  // Vulnerabilities
  getVulnerabilities: async (filters = {}) => {
    const params = new URLSearchParams(filters).toString();
    const response = await axios.get(`${API}/vulnerabilities?${params}`, { headers: getHeaders() });
    return response.data;
  },
  
  // AI Debug
  getAIDebug: async (repositoryId) => {
    const params = repositoryId ? `?repository_id=${repositoryId}` : '';
    const response = await axios.get(`${API}/ai-debug${params}`, { headers: getHeaders() });
    return response.data;
  },

  getAIDebugById: async (debugId) => {
    const response = await axios.get(`${API}/ai-debug/${debugId}`, { headers: getHeaders() });
    return response.data;
  },
  

  
  // Dashboard
  getDashboardStats: async () => {
    const response = await axios.get(`${API}/dashboard/stats`, { headers: getHeaders() });
    return response.data;
  },

  // GitHub Integration
  getGitHubAuthUrl: async () => {
    const response = await axios.get(`${API}/github/auth`, { headers: getHeaders() });
    return response.data;
  },

  handleGitHubCallback: async (code, state, installation_id, setup_action) => {
    // Build params object with only defined values
    const params = {};
    if (code) params.code = code;
    if (state) params.state = state;
    if (installation_id) params.installation_id = installation_id;
    if (setup_action) params.setup_action = setup_action;
    
    const response = await axios.post(
      `${API}/github/callback`,
      null,
      { 
        params,
        headers: getHeaders() 
      }
    );
    return response.data;
  },

  getGitHubConnectionStatus: async () => {
    const response = await axios.get(`${API}/github/status`, { headers: getHeaders() });
    return response.data;
  },

  syncGitHubInstallation: async () => {
    const response = await axios.post(`${API}/github/sync-installation`, null, { headers: getHeaders() });
    return response.data;
  },

  disconnectGitHub: async () => {
    const response = await axios.delete(`${API}/github/disconnect`, { headers: getHeaders() });
    return response.data;
  },

  getGitHubRepos: async () => {
    const response = await axios.get(`${API}/github/repos`, { headers: getHeaders() });
    return response.data;
  },

  connectGitHubRepos: async (repoIds) => {
    const response = await axios.post(
      `${API}/github/repos/connect`,
      { repo_ids: repoIds },
      { headers: getHeaders() }
    );
    return response.data;
  },

  disconnectGitHubRepos: async (repoIds) => {
    const response = await axios.post(
      `${API}/github/repos/disconnect`,
      { repo_ids: repoIds },
      { headers: getHeaders() }
    );
    return response.data;
  },

  // Repository Details - Branches & File Tree
  getRepoBranches: async (repoId) => {
    const response = await axios.get(`${API}/github/repos/${repoId}/branches`, { headers: getHeaders() });
    return response.data;
  },

  getRepoFileTree: async (repoId, branch = 'main') => {
    const response = await axios.get(
      `${API}/github/repos/${repoId}/tree`,
      { params: { branch }, headers: getHeaders() }
    );
    return response.data;
  },

  getRepoCommits: async (repoId, branch = 'main', limit = 20) => {
    const response = await axios.get(
      `${API}/github/repos/${repoId}/commits`,
      { params: { branch, limit }, headers: getHeaders() }
    );
    return response.data;
  },

  getASTTree: async (scanId, filePath, functionName) => {
    const response = await axios.get(
      `${API}/visualizer/ast-tree/${scanId}`,
      { 
        params: { file_path: filePath, function_name: functionName },
        headers: getHeaders() 
      }
    );
    return response.data;
  },

  // Scanning
  setupRepoForScanning: async (repoId) => {
    const response = await axios.post(
      `${API}/github/repos/${repoId}/setup`,
      {},
      { headers: getHeaders() }
    );
    return response.data;
  },

  startGitHubScan: async (repoId, scanMode = 'full', branch = 'main', baseCommit = null) => {
    const response = await axios.post(
      `${API}/github/repos/${repoId}/scan`,
      { scan_mode: scanMode, branch, base_commit: baseCommit },
      { headers: getHeaders() }
    );
    return response.data;
  },

  getRepoScans: async (repoId, limit = 10) => {
    const response = await axios.get(
      `${API}/github/repos/${repoId}/scans`,
      { params: { limit }, headers: getHeaders() }
    );
    return response.data;
  },

  // Visualizer
  getVisualizerTrace: async (scanId) => {
    const response = await axios.get(`${API}/visualizer/trace/${scanId}`, { headers: getHeaders() });
    return response.data;
  },

  getScanDebug: async (repoId) => {
    const response = await axios.get(
      `${API}/ai-debug/repo/${repoId}`,
      { headers: getHeaders() }
    );
    return response.data;
  },

  // Groq API Key Management
  saveGroqKey: async (apiKey) => {
    const response = await axios.put(
      `${API}/auth/groq-key`,
      { api_key: apiKey },
      { headers: getHeaders() }
    );
    return response.data;
  },

  deleteGroqKey: async () => {
    const response = await axios.delete(
      `${API}/auth/groq-key`,
      { headers: getHeaders() }
    );
    return response.data;
  },

};
export default apiClient;
