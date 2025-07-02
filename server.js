require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const PDFDocument = require('pdfkit');
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

// Enhanced AI summary generation
async function generateAISummary(content) {
  try {
    const technicalDetails = extractTechnicalDetails(content);
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

    return bulletPoints.join('\n');
  } catch (error) {
    console.error('Error generating AI summary:', error);
    return generateFallbackSummary(content);
  }
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
app.post('/summarize-pdf', async (req, res) => {
  try {
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: "Content is required" });
    }

    // Generate AI Summary
    const summaryBullets = await generateAISummary(content, 5);

    // Create PDF
    const doc = new PDFDocument();
    let buffers = [];

    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', () => {
      const pdfData = Buffer.concat(buffers);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename=summary.pdf');
      res.send(pdfData);
    });

    doc.fontSize(20).text('🛡️ Cybersecurity News Summary', { underline: true });
    doc.moveDown();

    summaryBullets.forEach(point => {
      doc.fontSize(12).text(point, { bulletRadius: 2 });
      doc.moveDown(0.5);
    });

    doc.end();

  } catch (err) {
    console.error("PDF generation error:", err.message);
    res.status(500).json({ error: "Failed to generate summary PDF" });
  }
});
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

// AI Summarization Endpoint
app.post('/api/summarize', async (req, res) => {
  try {
    const { content, articleId } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: "Content is required" });
    }

    const summary = await generateAISummary(content);
    
    res.json({ 
      summary,
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