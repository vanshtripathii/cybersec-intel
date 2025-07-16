require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const Parser = require('rss-parser');
const http = require('http');
const socketIo = require('socket.io');
const parser = new Parser();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;

// Hugging Face Configuration
const HF_API_TOKEN = process.env.HF_API_TOKEN;
const HF_API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn";

// News sources configuration
const NEWS_SOURCES = [
  {
    name: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    type: "rss"
  },
  {
    name: "The Hacker News",
    url: "https://feeds.feedburner.com/TheHackersNews",
    type: "rss"
  },
  {
    name: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    type: "rss"
  },
  {
    name: "Dark Reading",
    url: "https://www.darkreading.com/rss_simple.asp",
    type: "rss"
  },
  {
    name: "Cyberscoop",
    url: "https://www.cyberscoop.com/feed/",
    type: "rss"
  },
  {
    name: "Recorded Future",
    url: "https://www.recordedfuture.com/feed",
    type: "rss"
  }
];

// Cache for storing fetched articles
let articleCache = [];
let lastFetchTime = null;
const CACHE_DURATION = 15 * 60 * 1000; // 15 minutes

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Socket.IO integration
io.on('connection', (socket) => {
  console.log('New client connected');

  // Send initial data
  const sendInitialData = async () => {
    try {
      const threats = await fetchAllArticles();
      socket.emit('threatIntelUpdate', { 
        threats,
        stats: generateStats(threats)
      });
      socket.emit('recentAlertsUpdate', { 
        alerts: threats.slice(0, 5),
        stats: generateStats(threats.slice(0, 5))
      });
    } catch (error) {
      console.error('Error sending initial data:', error);
    }
  };

  sendInitialData();

  // Set up periodic updates
  const updateInterval = setInterval(async () => {
    try {
      const threats = await fetchAllArticles();
      io.emit('threatIntelUpdate', { 
        threats,
        stats: generateStats(threats)
      });
    } catch (error) {
      console.error('Error during periodic update:', error);
    }
  }, 30000); // Update every 30 seconds

  socket.on('disconnect', () => {
    console.log('Client disconnected');
    clearInterval(updateInterval);
  });

  // Handle initial data request from dashboard
  socket.on('getInitialData', async () => {
    try {
      const threats = await fetchAllArticles();
      socket.emit('threatIntelUpdate', { 
        threats,
        stats: generateStats(threats)
      });
      socket.emit('recentAlertsUpdate', { 
        alerts: threats.slice(0, 5),
        stats: generateStats(threats.slice(0, 5))
      });
    } catch (error) {
      console.error('Error sending initial data to dashboard:', error);
    }
  });

  // Handle summary requests
  socket.on('requestSummary', async ({ content, articleId }, callback) => {
    try {
      const { summary, iocs } = await generateAISummary(content);
      callback({
        success: true,
        summary,
        iocs,
        articleId
      });
    } catch (error) {
      console.error('Error generating summary:', error);
      callback({
        success: false,
        error: error.message
      });
    }
  });
});

// Generate statistics for threats
function generateStats(threats) {
  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  const sourceCounts = {};
  const tagCounts = {};
  let totalIOCs = 0;

  threats.forEach(threat => {
    severityCounts[threat.severity]++;
    
    if (!sourceCounts[threat.source]) {
      sourceCounts[threat.source] = 0;
    }
    sourceCounts[threat.source]++;
    
    if (threat.tags) {
      threat.tags.forEach(tag => {
        if (!tagCounts[tag]) {
          tagCounts[tag] = 0;
        }
        tagCounts[tag]++;
      });
    }
    
    if (threat.iocs) {
      totalIOCs += countIOCs(threat.iocs);
    }
  });

  return {
    totalThreats: threats.length,
    severityCounts,
    sourceCounts,
    tagCounts,
    totalIOCs,
    lastUpdated: new Date().toISOString()
  };
}

// Comprehensive IOC extraction function
function extractIOCs(content) {
  const text = content.toLowerCase();
  const originalContent = content;
  
  const iocs = {
    // Network-Based IOCs
    networkIOCs: {
      ipAddresses: [],
      domains: [],
      urls: [],
      emails: [],
      networkArtifacts: []
    },
    
    // File-Based IOCs
    fileIOCs: {
      hashes: [],
      filenames: [],
      filePaths: [],
      executableSignatures: []
    },
    
    // Host-Based IOCs
    hostIOCs: {
      registryKeys: [],
      scheduledTasks: [],
      processes: [],
      mutexes: []
    },
    
    // Behavioral IOCs
    behavioralIOCs: {
      systemBehavior: [],
      userBehavior: [],
      scriptExecution: []
    },
    
    // Threat Intelligence Tags
    threatIntelligence: {
      malwareFamilies: [],
      aptGroups: [],
      ttps: [],
      cves: []
    }
  };

  // Network-Based IOCs
  // Extract IP addresses (IPv4 and IPv6)
  iocs.networkIOCs.ipAddresses = [
    ...(originalContent.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []), // IPv4
    ...(originalContent.match(/\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi) || []) // IPv6
  ].filter((v, i, a) => a.indexOf(v) === i);

  // Extract domains (C2 domains)
  iocs.networkIOCs.domains = (originalContent.match(/(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g) || [])
    .filter(domain => !domain.match(/\.(html?|js|css|png|jpg|jpeg|gif|svg|xml|json|pdf|doc|docx|xls|xlsx|ppt|pptx)$/i))
    .filter(domain => !domain.match(/^(www\.|blog\.|news\.|support\.|help\.|docs\.|api\.|cdn\.|static\.)/i))
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract URLs (malicious links)
  iocs.networkIOCs.urls = (originalContent.match(/https?:\/\/[^\s"'<>]+/gi) || [])
    .filter(url => !url.match(/\.(jpg|png|gif|pdf|jpeg|svg|css|js|mp4|mp3|avi|mov|wav|zip|tar|gz|rar)$/i))
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract emails (phishing campaign senders)
  iocs.networkIOCs.emails = (originalContent.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g) || [])
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract network artifacts (ports, protocols)
  const portMatches = originalContent.match(/port\s+(\d+)/gi) || [];
  const protocolMatches = originalContent.match(/(tcp|udp|http|https|ftp|ssh|dns|smtp|pop3|imap)(?:\s+port\s+\d+)?/gi) || [];
  iocs.networkIOCs.networkArtifacts = [...portMatches, ...protocolMatches].filter((v, i, a) => a.indexOf(v) === i);

  // File-Based IOCs
  // Extract file hashes (MD5, SHA1, SHA256)
  iocs.fileIOCs.hashes = [
    ...(originalContent.match(/\b[a-fA-F0-9]{32}\b/g) || []), // MD5
    ...(originalContent.match(/\b[a-fA-F0-9]{40}\b/g) || []), // SHA1
    ...(originalContent.match(/\b[a-fA-F0-9]{64}\b/g) || [])  // SHA256
  ].filter((v, i, a) => a.indexOf(v) === i);

  // Extract filenames (known malware/dropper names)
  const filenamePatterns = [
    /\w+\.(?:exe|dll|bat|cmd|scr|vbs|js|jar|msi|zip|rar|7z|pdf|doc|docx|xls|xlsx|ppt|pptx)/gi,
    /["\']([^"']+\.(?:exe|dll|bat|cmd|scr|vbs|js|jar|msi))["\']/gi
  ];
  filenamePatterns.forEach(pattern => {
    const matches = originalContent.match(pattern) || [];
    iocs.fileIOCs.filenames.push(...matches);
  });
  iocs.fileIOCs.filenames = [...new Set(iocs.fileIOCs.filenames)];

  // Extract file paths
  const pathPatterns = [
    /[A-Za-z]:\\[^\s"'<>|]+/g, // Windows paths
    /\/[^\s"'<>|]+\/[^\s"'<>|]+/g, // Unix paths
    /%[A-Z_]+%\\[^\s"'<>|]+/g, // Windows environment variables
    /\$[A-Z_]+\/[^\s"'<>|]+/g // Unix environment variables
  ];
  pathPatterns.forEach(pattern => {
    const matches = originalContent.match(pattern) || [];
    iocs.fileIOCs.filePaths.push(...matches);
  });
  iocs.fileIOCs.filePaths = [...new Set(iocs.fileIOCs.filePaths)];

  // Extract executable signatures
  const signatureMatches = originalContent.match(/(?:certificate|signature|pe|portable executable|digital signature)[^\n.]{0,100}/gi) || [];
  iocs.fileIOCs.executableSignatures = [...new Set(signatureMatches)];

  // Host-Based IOCs
  // Extract registry keys
  const registryPatterns = [
    /HKEY_[A-Z_]+\\[^\s"'<>|]+/gi,
    /HKLM\\[^\s"'<>|]+/gi,
    /HKCU\\[^\s"'<>|]+/gi,
    /SOFTWARE\\[^\s"'<>|]+/gi
  ];
  registryPatterns.forEach(pattern => {
    const matches = originalContent.match(pattern) || [];
    iocs.hostIOCs.registryKeys.push(...matches);
  });
  iocs.hostIOCs.registryKeys = [...new Set(iocs.hostIOCs.registryKeys)];

  // Extract scheduled tasks/cron jobs
  const taskMatches = [
    ...(originalContent.match(/schtasks[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/crontab[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/scheduled task[^\n.]{0,100}/gi) || [])
  ];
  iocs.hostIOCs.scheduledTasks = [...new Set(taskMatches)];

  // Extract processes and services
  const processMatches = [
    ...(originalContent.match(/process[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/service[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/\w+\.exe/gi) || [])
  ];
  iocs.hostIOCs.processes = [...new Set(processMatches)];

  // Extract mutexes
  const mutexMatches = originalContent.match(/mutex[^\n.]{0,100}/gi) || [];
  iocs.hostIOCs.mutexes = [...new Set(mutexMatches)];

  // Behavioral IOCs
  // Extract system behavior patterns
  const behaviorPatterns = [
    /(?:cpu|memory|disk|network)\s+usage[^\n.]{0,100}/gi,
    /(?:unusual|suspicious|anomalous)\s+(?:activity|behavior|pattern)[^\n.]{0,100}/gi,
    /(?:high|excessive|abnormal)\s+(?:cpu|memory|disk|network)[^\n.]{0,100}/gi
  ];
  behaviorPatterns.forEach(pattern => {
    const matches = originalContent.match(pattern) || [];
    iocs.behavioralIOCs.systemBehavior.push(...matches);
  });
  iocs.behavioralIOCs.systemBehavior = [...new Set(iocs.behavioralIOCs.systemBehavior)];

  // Extract user behavior anomalies
  const userBehaviorMatches = [
    ...(originalContent.match(/(?:login|logon|authentication)[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/(?:unauthorized|unusual|suspicious)\s+(?:access|login|activity)[^\n.]{0,100}/gi) || [])
  ];
  iocs.behavioralIOCs.userBehavior = [...new Set(userBehaviorMatches)];

  // Extract PowerShell/Script execution
  const scriptMatches = [
    ...(originalContent.match(/powershell[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/cmd\.exe[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/(?:obfuscated|encoded|base64)[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/wscript[^\n.]{0,100}/gi) || []),
    ...(originalContent.match(/cscript[^\n.]{0,100}/gi) || [])
  ];
  iocs.behavioralIOCs.scriptExecution = [...new Set(scriptMatches)];

  // Threat Intelligence Tags
  // Extract malware family names
  const malwareFamilies = [
    'emotet', 'cobalt strike', 'trickbot', 'qakbot', 'ryuk', 'conti', 'ransomware',
    'trojans', 'backdoor', 'rootkit', 'keylogger', 'spyware', 'adware', 'worm',
    'virus', 'botnet', 'banking trojan', 'rat', 'stealer', 'loader', 'dropper',
    'mimikatz', 'metasploit', 'empire', 'covenant', 'pupy', 'sliver', 'havoc',
    'lockbit', 'blackcat', 'royal', 'clop', 'akira', 'play', 'bianlian'
  ];
  
  malwareFamilies.forEach(family => {
    if (text.includes(family)) {
      iocs.threatIntelligence.malwareFamilies.push(family);
    }
  });
  iocs.threatIntelligence.malwareFamilies = [...new Set(iocs.threatIntelligence.malwareFamilies)];

  // Extract APT groups
  const aptGroups = [
    'apt1', 'apt28', 'apt29', 'apt32', 'apt34', 'apt40', 'apt41', 'lazarus',
    'fin7', 'fin8', 'carbanak', 'ta505', 'ta506', 'wizard spider', 'fancy bear',
    'cozy bear', 'sandworm', 'turla', 'equation group', 'oceanlotus', 'putter panda',
    'comment crew', 'dragonfly', 'energetic bear', 'kimsuky', 'andariel', 'bluenoroff'
  ];
  
  aptGroups.forEach(group => {
    if (text.includes(group)) {
      iocs.threatIntelligence.aptGroups.push(group);
    }
  });
  iocs.threatIntelligence.aptGroups = [...new Set(iocs.threatIntelligence.aptGroups)];

  // Extract TTPs (MITRE ATT&CK techniques)
  const ttps = [
    'spearphishing', 'watering hole', 'drive-by compromise', 'exploit public-facing application',
    'valid accounts', 'remote desktop protocol', 'lateral movement', 'privilege escalation',
    'credential dumping', 'pass the hash', 'golden ticket', 'silver ticket', 'dcsync',
    'powershell empire', 'living off the land', 'fileless malware', 'process injection',
    'dll injection', 'code injection', 'reflective dll loading', 'process hollowing',
    'command and control', 'c2', 'data exfiltration', 'persistence', 'defense evasion',
    'discovery', 'collection', 'impact', 'initial access', 'execution'
  ];
  
  ttps.forEach(ttp => {
    if (text.includes(ttp)) {
      iocs.threatIntelligence.ttps.push(ttp);
    }
  });
  iocs.threatIntelligence.ttps = [...new Set(iocs.threatIntelligence.ttps)];

  // Extract CVEs
  iocs.threatIntelligence.cves = (originalContent.match(/\bCVE-\d{4}-\d{4,7}\b/g) || [])
    .filter((v, i, a) => a.indexOf(v) === i);

  // Filter out empty arrays and categories
  Object.keys(iocs).forEach(category => {
    Object.keys(iocs[category]).forEach(key => {
      if (Array.isArray(iocs[category][key]) && iocs[category][key].length === 0) {
        delete iocs[category][key];
      }
    });
    
    // Remove empty categories
    if (Object.keys(iocs[category]).length === 0) {
      delete iocs[category];
    }
  });

  return iocs;
}

// Fetch articles from all sources
async function fetchAllArticles() {
  const now = Date.now();
  
  if (lastFetchTime && (now - lastFetchTime) < CACHE_DURATION) {
    return articleCache;
  }

  try {
    const fetchPromises = NEWS_SOURCES.map(source => fetchRSSFeed(source));
    const results = await Promise.all(fetchPromises);
    
    articleCache = results.flat().map(article => ({
      ...article,
      id: uuidv4(),
      severity: determineSeverity(article.title, article.description),
      iocs: extractIOCs(article.title + ' ' + article.description),
      tags: extractTags(article.title, article.description),
      technicalDetails: extractTechnicalDetails(article.title + ' ' + article.description)
    }));
    
    lastFetchTime = now;
    return articleCache;
  } catch (error) {
    console.error('Error fetching articles:', error);
    return articleCache.length ? articleCache : [];
  }
}

// Fetch and parse RSS feed
async function fetchRSSFeed(source) {
  try {
    const feed = await parser.parseURL(source.url);
    return feed.items.map(item => ({
      title: item.title,
      description: item.contentSnippet || item.content || item.summary || '',
      url: item.link,
      source: source.name,
      publishedAt: item.isoDate || item.pubDate || new Date().toISOString()
    }));
  } catch (error) {
    console.error(`Error fetching ${source.name}:`, error);
    return [];
  }
}

// Determine severity based on content
function determineSeverity(title, content) {
  const text = `${title} ${content}`.toLowerCase();
  
  if (text.includes('zero-day') || text.includes('critical') || text.includes('emergency')) {
    return 'critical';
  }
  if (text.includes('exploit') || text.includes('high') || text.includes('attack')) {
    return 'high';
  }
  if (text.includes('vulnerability') || text.includes('medium') || text.includes('risk')) {
    return 'medium';
  }
  return 'low';
}

// Extract tags from content
function extractTags(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  const tags = [];
  
  if (text.includes('ransomware')) tags.push('ransomware');
  if (text.includes('phishing')) tags.push('phishing');
  if (text.includes('malware')) tags.push('malware');
  if (text.includes('vulnerability')) tags.push('vulnerability');
  if (text.includes('breach')) tags.push('breach');
  if (text.includes('iot')) tags.push('iot');
  if (text.includes('zero-day')) tags.push('zero-day');
  if (text.includes('exploit')) tags.push('exploit');
  if (text.includes('apt')) tags.push('apt');
  if (text.includes('botnet')) tags.push('botnet');
  
  return tags.length ? tags : ['cybersecurity'];
}

// Extract technical details from content
function extractTechnicalDetails(content) {
  const details = [];
  
  // Extract CVEs
  const cveMatches = content.match(/\bCVE-\d{4}-\d{4,7}\b/g) || [];
  details.push(...cveMatches.map(cve => `Vulnerability: ${cve}`));

  // Extract CVSS scores
  const cvssMatches = content.match(/CVSS:?\s*[\d.]+\s*\(?\w+\)?/gi) || [];
  details.push(...cvssMatches.map(cvss => `Severity Score: ${cvss.trim()}`));

  // Extract other technical indicators
  if (content.includes('zero-day')) details.push('Zero-day vulnerability');
  if (content.includes('remote code execution')) details.push('Remote Code Execution (RCE)');
  if (content.includes('privilege escalation')) details.push('Privilege Escalation');
  if (content.includes('buffer overflow')) details.push('Buffer Overflow');
  if (content.includes('sql injection')) details.push('SQL Injection');
  if (content.includes('cross-site scripting')) details.push('Cross-Site Scripting (XSS)');

  return details.slice(0, 5);
}

// Count total IOCs for display purposes
function countIOCs(iocs) {
  let total = 0;
  
  Object.values(iocs).forEach(category => {
    if (typeof category === 'object' && category !== null) {
      Object.values(category).forEach(arr => {
        if (Array.isArray(arr)) {
          total += arr.length;
        }
      });
    }
  });
  
  return total;
}

// Enhanced AI summary generation with IOCs
async function generateAISummary(content) {
  try {
    const technicalDetails = extractTechnicalDetails(content);
    const iocs = extractIOCs(content);
    const contentToSummarize = content.substring(0, 3000);

    const response = await axios.post(
      HF_API_URL,
      { 
        inputs: contentToSummarize,
        parameters: {
          max_length: 300,
          min_length: 150,
          do_sample: false
        }
      },
      {
        headers: {
          Authorization: `Bearer ${HF_API_TOKEN}`,
          'Content-Type': 'application/json'
        },
        timeout: 60000
      }
    );

    // Process the summary into bullet points
    const summary = response.data[0]?.summary_text || '';
    const bulletPoints = summary.split('. ')
      .filter(s => s.trim().length > 0)
      .slice(0, 6)
      .map(sentence => `• ${sentence.trim().replace(/\.$/, '')}`);

    // Add technical details if found
    if (technicalDetails.length > 0) {
      bulletPoints.push('\nTechnical Details:');
      bulletPoints.push(...technicalDetails.map(detail => `  • ${detail}`));
    }

    return {
      summary: bulletPoints.join('\n'),
      iocs: iocs
    };
  } catch (error) {
    console.error('Error generating AI summary:', error);
    return {
      summary: generateFallbackSummary(content),
      iocs: extractIOCs(content) // Ensure IOCs are extracted even if summary fails
    };
  }
}

// Fallback summary generation
function generateFallbackSummary(content) {
  // Get the most important sentences
  const sentences = content.split(/[.!?]+/)
    .filter(s => s.trim().length > 20)
    .sort((a, b) => b.length - a.length)
    .slice(0, 5);

  // Create bullet points
  const bulletPoints = sentences.map(s => `• ${s.trim()}`);
  
  // Add technical details if found
  const techDetails = extractTechnicalDetails(content);
  if (techDetails.length > 0) {
    bulletPoints.push('\nTechnical Details:');
    bulletPoints.push(...techDetails.map(d => `  • ${d}`));
  }

  return bulletPoints.join('\n');
}

// API Endpoints
// In your server code (app.get('/api/threats'))
app.get('/api/threats', async (req, res) => {
  try {
    const { start, end } = req.query;
    const allArticles = await fetchAllArticles();
    
    let results = [...allArticles];

    if (start && end) {
      results = results.filter(article => {
        const articleDate = new Date(article.publishedAt);
        return articleDate >= new Date(start) && articleDate <= new Date(end);
      });
    }

    res.json({
      total: results.length,
      threats: results,
      stats: generateStats(results),
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error in /api/threats:', error);
    res.status(500).json({ error: "Failed to fetch threats" });
  }
});

// Get IOCs for a specific article
app.get('/api/iocs/:articleId', async (req, res) => {
  try {
    const { articleId } = req.params;
    const allArticles = await fetchAllArticles();
    
    const article = allArticles.find(a => a.id === articleId);
    if (!article) {
      return res.status(404).json({ error: "Article not found" });
    }

    res.json({
      articleId,
      title: article.title,
      source: article.source,
      iocs: article.iocs || {},
      technicalDetails: article.technicalDetails || [],
      severity: article.severity,
      publishedAt: article.publishedAt,
      iocCount: countIOCs(article.iocs || {})
    });
  } catch (error) {
    console.error('Error in /api/iocs:', error);
    res.status(500).json({ error: "Failed to fetch IOCs" });
  }
});

// Get all IOCs across all articles
app.get('/api/iocs', async (req, res) => {
  try {
    const allArticles = await fetchAllArticles();
    
    const aggregatedIOCs = {
      networkIOCs: {
        ipAddresses: [],
        domains: [],
        urls: [],
        emails: [],
        networkArtifacts: []
      },
      fileIOCs: {
        hashes: [],
        filenames: [],
        filePaths: [],
        executableSignatures: []
      },
      hostIOCs: {
        registryKeys: [],
        scheduledTasks: [],
        processes: [],
        mutexes: []
      },
      behavioralIOCs: {
        systemBehavior: [],
        userBehavior: [],
        scriptExecution: []
      },
      threatIntelligence: {
        malwareFamilies: [],
        aptGroups: [],
        ttps: [],
        cves: []
      }
    };

    // Aggregate all IOCs
    allArticles.forEach(article => {
      if (article.iocs) {
        Object.keys(aggregatedIOCs).forEach(categoryKey => {
          if (article.iocs[categoryKey]) {
            Object.keys(aggregatedIOCs[categoryKey]).forEach(iocType => {
              if (article.iocs[categoryKey][iocType]) {
                aggregatedIOCs[categoryKey][iocType].push(...article.iocs[categoryKey][iocType]);
              }
            });
          }
        });
      }
    });

    // Remove duplicates
    Object.keys(aggregatedIOCs).forEach(categoryKey => {
      Object.keys(aggregatedIOCs[categoryKey]).forEach(iocType => {
        aggregatedIOCs[categoryKey][iocType] = [...new Set(aggregatedIOCs[categoryKey][iocType])];
      });
    });

    // Calculate summary statistics
    const summary = {
      network: {
        totalIPs: aggregatedIOCs.networkIOCs.ipAddresses?.length || 0,
        totalDomains: aggregatedIOCs.networkIOCs.domains?.length || 0,
        totalURLs: aggregatedIOCs.networkIOCs.urls?.length || 0,
        totalEmails: aggregatedIOCs.networkIOCs.emails?.length || 0,
        totalNetworkArtifacts: aggregatedIOCs.networkIOCs.networkArtifacts?.length || 0
      },
      file: {
        totalHashes: aggregatedIOCs.fileIOCs.hashes?.length || 0,
        totalFilenames: aggregatedIOCs.fileIOCs.filenames?.length || 0,
        totalFilePaths: aggregatedIOCs.fileIOCs.filePaths?.length || 0,
        totalSignatures: aggregatedIOCs.fileIOCs.executableSignatures?.length || 0
      },
      host: {
        totalRegistryKeys: aggregatedIOCs.hostIOCs.registryKeys?.length || 0,
        totalScheduledTasks: aggregatedIOCs.hostIOCs.scheduledTasks?.length || 0,
        totalProcesses: aggregatedIOCs.hostIOCs.processes?.length || 0,
        totalMutexes: aggregatedIOCs.hostIOCs.mutexes?.length || 0
      },
      behavioral: {
        totalSystemBehavior: aggregatedIOCs.behavioralIOCs.systemBehavior?.length || 0,
        totalUserBehavior: aggregatedIOCs.behavioralIOCs.userBehavior?.length || 0,
        totalScriptExecution: aggregatedIOCs.behavioralIOCs.scriptExecution?.length || 0
      },
      threatIntel: {
        totalMalwareFamilies: aggregatedIOCs.threatIntelligence.malwareFamilies?.length || 0,
        totalAPTGroups: aggregatedIOCs.threatIntelligence.aptGroups?.length || 0,
        totalTTPs: aggregatedIOCs.threatIntelligence.ttps?.length || 0,
        totalCVEs: aggregatedIOCs.threatIntelligence.cves?.length || 0
      }
    };

    res.json({
      totalArticles: allArticles.length,
      articlesWithIOCs: allArticles.filter(a => a.iocs && Object.keys(a.iocs).length > 0).length,
      aggregatedIOCs,
      summary,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error in /api/iocs:', error);
    res.status(500).json({ error: "Failed to fetch aggregated IOCs" });
  }
});

// AI Summarization Endpoint with IOCs
app.post('/api/summarize', async (req, res) => {
  try {
    const { content, articleId } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: "Content is required" });
    }

    const { summary, iocs } = await generateAISummary(content);
    
    res.json({ 
      summary,
      iocs,
      articleId
    });
  } catch (error) {
    console.error('Error in /api/summarize:', error);
    
    if (error.message.includes('rate limit') || error.message.includes('loading')) {
      return res.status(503).json({ error: error.message });
    }
    
    res.status(500).json({ 
      error: "Failed to generate summary",
      details: error.message
    });
  }
});

// ==============================================
// NEW REPORTS ENDPOINTS
// ==============================================

// Generate daily threat report
app.get('/api/reports/daily', async (req, res) => {
  try {
    const allArticles = await fetchAllArticles();
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todaysThreats = allArticles.filter(article => {
      const articleDate = new Date(article.publishedAt);
      return articleDate >= today;
    });

    if (todaysThreats.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: "No threats found for today"
      });
    }

    // Generate report data
    const report = {
      date: today.toISOString().split('T')[0],
      totalThreats: todaysThreats.length,
      stats: generateStats(todaysThreats),
      topThreats: todaysThreats
        .sort((a, b) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[b.severity] - severityOrder[a.severity];
        })
        .slice(0, 10),
      notableIOCs: aggregateTopIOCs(todaysThreats)
    };

    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Error generating daily report:', error);
    res.status(500).json({ 
      success: false,
      error: "Failed to generate daily report"
    });
  }
});

// Generate weekly threat report
app.get('/api/reports/weekly', async (req, res) => {
  try {
    const allArticles = await fetchAllArticles();
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    oneWeekAgo.setHours(0, 0, 0, 0);
    
    const weeklyThreats = allArticles.filter(article => {
      const articleDate = new Date(article.publishedAt);
      return articleDate >= oneWeekAgo;
    });

    if (weeklyThreats.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: "No threats found for this week"
      });
    }

    // Generate report data
    const report = {
      startDate: oneWeekAgo.toISOString().split('T')[0],
      endDate: new Date().toISOString().split('T')[0],
      totalThreats: weeklyThreats.length,
      stats: generateStats(weeklyThreats),
      dailyBreakdown: generateDailyBreakdown(weeklyThreats),
      topThreats: weeklyThreats
        .sort((a, b) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[b.severity] - severityOrder[a.severity];
        })
        .slice(0, 15),
      notableIOCs: aggregateTopIOCs(weeklyThreats),
      trendingTags: getTrendingTags(weeklyThreats)
    };

    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Error generating weekly report:', error);
    res.status(500).json({ 
      success: false,
      error: "Failed to generate weekly report"
    });
  }
});

// Generate custom report based on date range
app.get('/api/reports/custom', async (req, res) => {
  try {
    const { start, end } = req.query;
    
    if (!start || !end) {
      return res.status(400).json({ 
        success: false,
        error: "Both start and end dates are required"
      });
    }

    const startDate = new Date(start);
    const endDate = new Date(end);
    
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).json({ 
        success: false,
        error: "Invalid date format. Use YYYY-MM-DD"
      });
    }

    const allArticles = await fetchAllArticles();
    
    const filteredThreats = allArticles.filter(article => {
      const articleDate = new Date(article.publishedAt);
      return articleDate >= startDate && articleDate <= endDate;
    });

    if (filteredThreats.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: `No threats found between ${start} and ${end}`
      });
    }

    // Generate report data
    const report = {
      startDate: start,
      endDate: end,
      totalThreats: filteredThreats.length,
      stats: generateStats(filteredThreats),
      dailyBreakdown: generateDailyBreakdown(filteredThreats),
      topThreats: filteredThreats
        .sort((a, b) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[b.severity] - severityOrder[a.severity];
        })
        .slice(0, 20),
      notableIOCs: aggregateTopIOCs(filteredThreats),
      trendingTags: getTrendingTags(filteredThreats),
      sourceDistribution: getSourceDistribution(filteredThreats)
    };

    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Error generating custom report:', error);
    res.status(500).json({ 
      success: false,
      error: "Failed to generate custom report"
    });
  }
});

// Generate threat actor report
app.get('/api/reports/threat-actors', async (req, res) => {
  try {
    const allArticles = await fetchAllArticles();
    const oneMonthAgo = new Date();
    oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
    oneMonthAgo.setHours(0, 0, 0, 0);
    
    const recentThreats = allArticles.filter(article => {
      const articleDate = new Date(article.publishedAt);
      return articleDate >= oneMonthAgo;
    });

    // Extract threat actor information
    const threatActors = {};
    
    recentThreats.forEach(article => {
      if (article.iocs?.threatIntelligence?.aptGroups) {
        article.iocs.threatIntelligence.aptGroups.forEach(group => {
          if (!threatActors[group]) {
            threatActors[group] = {
              count: 0,
              articles: [],
              malwareFamilies: new Set(),
              ttps: new Set(),
              iocs: {
                networkIOCs: new Set(),
                fileIOCs: new Set(),
                hostIOCs: new Set()
              }
            };
          }
          
          threatActors[group].count++;
          threatActors[group].articles.push({
            title: article.title,
            url: article.url,
            publishedAt: article.publishedAt,
            severity: article.severity
          });
          
          // Add associated malware families
          if (article.iocs.threatIntelligence.malwareFamilies) {
            article.iocs.threatIntelligence.malwareFamilies.forEach(family => {
              threatActors[group].malwareFamilies.add(family);
            });
          }
          
          // Add TTPs
          if (article.iocs.threatIntelligence.ttps) {
            article.iocs.threatIntelligence.ttps.forEach(ttp => {
              threatActors[group].ttps.add(ttp);
            });
          }
          
          // Add notable IOCs
          if (article.iocs.networkIOCs?.domains) {
            article.iocs.networkIOCs.domains.forEach(domain => {
              threatActors[group].iocs.networkIOCs.add(domain);
            });
          }
          
          if (article.iocs.fileIOCs?.hashes) {
            article.iocs.fileIOCs.hashes.forEach(hash => {
              threatActors[group].iocs.fileIOCs.add(hash);
            });
          }
        });
      }
    });

    // Convert sets to arrays for response
    const formattedActors = Object.keys(threatActors).map(name => {
      return {
        name,
        count: threatActors[name].count,
        articles: threatActors[name].articles,
        malwareFamilies: Array.from(threatActors[name].malwareFamilies),
        ttps: Array.from(threatActors[name].ttps),
        iocs: {
          networkIOCs: Array.from(threatActors[name].iocs.networkIOCs).slice(0, 5),
          fileIOCs: Array.from(threatActors[name].iocs.fileIOCs).slice(0, 5),
          hostIOCs: Array.from(threatActors[name].iocs.hostIOCs).slice(0, 5)
        }
      };
    });

    res.json({
      success: true,
      threatActors: formattedActors,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error generating threat actor report:', error);
    res.status(500).json({ 
      success: false,
      error: "Failed to generate threat actor report"
    });
  }
});

// Helper function to generate daily breakdown
function generateDailyBreakdown(articles) {
  const dailyCounts = {};
  
  articles.forEach(article => {
    const date = new Date(article.publishedAt).toISOString().split('T')[0];
    
    if (!dailyCounts[date]) {
      dailyCounts[date] = {
        date,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      };
    }
    
    dailyCounts[date].total++;
    dailyCounts[date][article.severity]++;
  });
  
  return Object.values(dailyCounts).sort((a, b) => new Date(a.date) - new Date(b.date));
}

// Helper function to aggregate top IOCs
function aggregateTopIOCs(articles) {
  const iocCounts = {
    domains: {},
    ipAddresses: {},
    hashes: {},
    cves: {},
    malwareFamilies: {}
  };
  
  articles.forEach(article => {
    if (article.iocs) {
      // Count domains
      if (article.iocs.networkIOCs?.domains) {
        article.iocs.networkIOCs.domains.forEach(domain => {
          iocCounts.domains[domain] = (iocCounts.domains[domain] || 0) + 1;
        });
      }
      
      // Count IPs
      if (article.iocs.networkIOCs?.ipAddresses) {
        article.iocs.networkIOCs.ipAddresses.forEach(ip => {
          iocCounts.ipAddresses[ip] = (iocCounts.ipAddresses[ip] || 0) + 1;
        });
      }
      
      // Count hashes
      if (article.iocs.fileIOCs?.hashes) {
        article.iocs.fileIOCs.hashes.forEach(hash => {
          iocCounts.hashes[hash] = (iocCounts.hashes[hash] || 0) + 1;
        });
      }
      
      // Count CVEs
      if (article.iocs.threatIntelligence?.cves) {
        article.iocs.threatIntelligence.cves.forEach(cve => {
          iocCounts.cves[cve] = (iocCounts.cves[cve] || 0) + 1;
        });
      }
      
      // Count malware families
      if (article.iocs.threatIntelligence?.malwareFamilies) {
        article.iocs.threatIntelligence.malwareFamilies.forEach(family => {
          iocCounts.malwareFamilies[family] = (iocCounts.malwareFamilies[family] || 0) + 1;
        });
      }
    }
  });
  
  // Get top 5 for each IOC type
  return {
    domains: Object.entries(iocCounts.domains)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([domain, count]) => ({ domain, count })),
    ipAddresses: Object.entries(iocCounts.ipAddresses)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count })),
    hashes: Object.entries(iocCounts.hashes)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([hash, count]) => ({ hash, count })),
    cves: Object.entries(iocCounts.cves)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([cve, count]) => ({ cve, count })),
    malwareFamilies: Object.entries(iocCounts.malwareFamilies)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([family, count]) => ({ family, count }))
  };
}

// Helper function to get trending tags
function getTrendingTags(articles) {
  const tagCounts = {};
  
  articles.forEach(article => {
    article.tags.forEach(tag => {
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    });
  });
  
  return Object.entries(tagCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tag, count]) => ({ tag, count }));
}

// Helper function to get source distribution
function getSourceDistribution(articles) {
  const sourceCounts = {};
  
  articles.forEach(article => {
    sourceCounts[article.source] = (sourceCounts[article.source] || 0) + 1;
  });
  
  return Object.entries(sourceCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([source, count]) => ({ source, count }));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date(),
    sources: NEWS_SOURCES.map(s => s.name),
    lastFetchTime: lastFetchTime ? new Date(lastFetchTime) : null,
    hfStatus: HF_API_TOKEN ? "Configured" : "Missing Token",
    articlesInCache: articleCache.length,
    articlesWithIOCs: articleCache.filter(a => a.iocs && Object.keys(a.iocs).length > 0).length,
    socketConnections: io.engine.clientsCount
  });
});
// Serve reports page
app.get('/reports', (req, res) => {
  res.sendFile(__dirname + '/reports.html');
});
// Start server
server.listen(PORT, async () => {
  console.log(`\n🚀 Cybersecurity Threat Intelligence Server running on http://localhost:${PORT}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('\n🎯 Available endpoints:');
  console.log('  📊 /api/threats - Combined threat intelligence');
  console.log('  🔍 /api/iocs - Indicators of Compromise');
  console.log('  🤖 /api/summarize - Threat summaries');
  console.log('  📈 /api/reports/daily - Daily threat report');
  console.log('  📈 /api/reports/weekly - Weekly threat report');
  console.log('  📈 /api/reports/custom - Custom date range report');
  console.log('  🕵️ /api/reports/threat-actors - Threat actor analysis');
  console.log('  🏥 /health - System health check');
  console.log('\n📡 Socket.IO: Real-time threat broadcasting enabled');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  if (!HF_API_TOKEN) {
    console.error('⚠️  Hugging Face API token not found in environment variables');
  } else {
    console.log('🤖 Hugging Face AI summarization enabled');
  }
  
  try {
    await fetchAllArticles();
    console.log('\n🔍 Initial article fetch completed');
    console.log(`📊 Articles with IOCs: ${articleCache.filter(a => a.iocs && Object.keys(a.iocs).length > 0).length}/${articleCache.length}`);
  } catch (error) {
    console.error('Initial fetch failed:', error);
  }
});
