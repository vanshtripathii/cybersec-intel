require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const Parser = require('rss-parser');
const parser = new Parser();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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
    url: "https://www.darkreading.com/rss.xml",
    type: "rss"
  },
  {
    name: "Cyberscoop",
    url: "https://www.cyberscoop.com/feed/",
    type: "rss"
  },
  {
    name: "Recorded Future",
    url: "https://www.recordedfuture.com/news/rss.xml",
    type: "rss"
  }
];

// Cache for storing fetched articles
let articleCache = [];
let lastFetchTime = null;
const CACHE_DURATION = 15 * 60 * 1000; // 15 minutes

// Fetch articles from all sources
async function fetchAllArticles() {
  const now = Date.now();
  
  if (lastFetchTime && (now - lastFetchTime) < CACHE_DURATION) {
    return articleCache;
  }

  const allArticles = [];
  
  try {
    const fetchPromises = NEWS_SOURCES.map(source => {
      if (source.type === 'rss') {
        return fetchRSSFeed(source);
      }
      return Promise.resolve([]);
    });

    const results = await Promise.allSettled(fetchPromises);
    
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        allArticles.push(...result.value);
      }
    });

    articleCache = processArticles(allArticles);
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
      id: uuidv4(),
      title: item.title,
      description: item.contentSnippet || item.content || '',
      url: item.link,
      source: source.name,
      publishedAt: item.isoDate || item.pubDate || new Date().toISOString(),
      severity: determineSeverity(item.title, item.content)
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

// Process and normalize articles
function processArticles(articles) {
  return articles.map(article => ({
    ...article,
    tags: extractTags(article.title, article.description)
  }));
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

  return details.slice(0, 3);
}

// Enhanced IOC extraction function
function extractIOCs(content) {
  const iocs = {
    hashes: [],
    domains: [],
    ips: [],
    urls: [],
    emails: [],
    cves: []
  };

  // Extract MD5, SHA1, SHA256 hashes
  iocs.hashes = [
    ...(content.match(/\b[a-fA-F0-9]{32}\b/g) || []), // MD5
    ...(content.match(/\b[a-fA-F0-9]{40}\b/g) || []), // SHA1
    ...(content.match(/\b[a-fA-F0-9]{64}\b/g) || [])  // SHA256
  ].filter((v, i, a) => a.indexOf(v) === i); // Remove duplicates

  // Extract domains (more comprehensive regex)
  iocs.domains = (content.match(/(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g) || [])
    .filter(domain => !domain.match(/\.(com|org|net|gov|edu|io|html?|js|css|png|jpg|jpeg|gif|svg|xml|json)$/i)) // Filter out common TLDs and file extensions
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract IP addresses (including IPv6)
  iocs.ips = [
    ...(content.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []), // IPv4
    ...(content.match(/\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi) || []) // IPv6
  ].filter((v, i, a) => a.indexOf(v) === i);

  // Extract URLs (excluding common image/file extensions)
  iocs.urls = (content.match(/https?:\/\/[^\s"'<>]+/gi) || [])
    .filter(url => !url.match(/\.(jpg|png|gif|pdf|jpeg|svg|css|js|mp4|mp3|avi|mov|wav|zip|tar|gz|rar)$/i))
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract emails
  iocs.emails = (content.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g) || [])
    .filter((v, i, a) => a.indexOf(v) === i);

  // Extract CVEs
  iocs.cves = (content.match(/\bCVE-\d{4}-\d{4,7}\b/g) || [])
    .filter((v, i, a) => a.indexOf(v) === i);

  // Filter out empty arrays
  Object.keys(iocs).forEach(key => {
    if (Array.isArray(iocs[key]) && iocs[key].length === 0) {
      delete iocs[key];
    }
  });

  return iocs;
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
        timeout: 30000
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

    res.json(results);
  } catch (error) {
    console.error('Error in /api/threats:', error);
    res.status(500).json({ error: "Failed to fetch threats" });
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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date(),
    sources: NEWS_SOURCES.map(s => s.name),
    lastFetchTime: lastFetchTime ? new Date(lastFetchTime) : null,
    hfStatus: HF_API_TOKEN ? "Configured" : "Missing Token"
  });
});

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);
  
  if (!HF_API_TOKEN) {
    console.error('Hugging Face API token not found in environment variables');
  } else {
    console.log('Hugging Face API connected');
  }
  
  try {
    await fetchAllArticles();
    console.log('Initial article fetch completed');
  } catch (error) {
    console.error('Initial fetch failed:', error);
  }
});
