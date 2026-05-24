const express = require('express');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;
const DATA_FILE = path.join(__dirname, 'data.json');

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: false,
  methods: ['GET'],
  optionsSuccessStatus: 200
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

const scrapeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1,
  message: 'Only one scrape per hour allowed.',
  skip: (req) => req.ip === '127.0.0.1'
});

app.use(limiter);
app.use(express.json({ limit: '1mb' }));

// Serve static files from React build (when ready)
app.use(express.static(path.join(__dirname, 'frontend/build'), { fallthrough: true, maxAge: '1h' }));

// API Routes
app.get('/api/scrape', scrapeLimiter, (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.SCRAPE_API_KEY && process.env.SCRAPE_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  console.log('Starting scrape...');
  const scraper = spawn('node', [path.join(__dirname, 'index.js')], { 
    cwd: __dirname,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 300000
  });
  let errorOutput = '';
  let outputSize = 0;
  const MAX_OUTPUT = 10000;
  
  scraper.stdout.on('data', (data) => {
    outputSize += data.length;
    if (outputSize <= MAX_OUTPUT) console.log(data.toString().slice(0, 100));
  });

  scraper.stderr.on('data', (data) => {
    if (errorOutput.length < MAX_OUTPUT) {
      errorOutput += data.toString();
    }
    console.error(data.toString().slice(0, 100));
  });

  scraper.on('close', (code) => {
    if (code === 0 && fs.existsSync(DATA_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
        res.json({ success: true, count: data.length, message: 'Scraping complete' });
      } catch (e) {
        res.status(500).json({ success: false, error: 'Invalid data file' });
      }
    } else {
      res.status(500).json({ success: false, error: errorOutput || 'Scraping failed' });
    }
  });

  scraper.on('error', (err) => {
    console.error('Scraper error:', err);
    res.status(500).json({ success: false, error: 'Scraper process error' });
  });

  setTimeout(() => {
    if (scraper.exitCode === null) {
      scraper.kill();
      res.status(500).json({ success: false, error: 'Scraping timeout' });
    }
  }, 300000);
});

app.get('/api/programs', (req, res) => {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
      res.json(data);
    } else {
      res.json([]);
    }
  } catch (e) {
    console.error('Error reading data:', e);
    res.json([]);
  }
});

app.get('/api/stats', (req, res) => {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
      const stats = {
        total: data.length,
        api: data.filter(p => p.scopes && p.scopes.includes('api')).length,
        android: data.filter(p => p.scopes && p.scopes.includes('android')).length,
        domain: data.filter(p => p.scopes && p.scopes.includes('domain')).length,
        platforms: {
          hackerone: data.filter(p => p.platform === 'HackerOne').length,
          bugcrowd: data.filter(p => p.platform === 'Bugcrowd').length,
          intigriti: data.filter(p => p.platform === 'Intigriti').length
        }
      };
      res.json(stats);
    } else {
      res.json({ total: 0, api: 0, android: 0, domain: 0, platforms: {} });
    }
  } catch (e) {
    res.json({ total: 0, api: 0, android: 0, domain: 0, platforms: {} });
  }
});

// Catch all - serve simple HTML page or React index.html
app.use((req, res) => {
  const buildPath = path.join(__dirname, 'frontend/build/index.html');
  if (fs.existsSync(buildPath)) {
    res.sendFile(buildPath);
  } else {
    // Serve a simple HTML page if React build doesn't exist
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Bug Bounty Scope Aggregator</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          h1 { color: #333; }
          .stats { margin: 20px 0; padding: 10px; background: #f0f0f0; }
          .loading { color: #666; font-style: italic; }
        </style>
      </head>
      <body>
        <h1>🐛 Bug Bounty Scope Aggregator</h1>
        <p>Server is running! API endpoints available:</p>
        <ul>
          <li><code>GET /api/stats</code> - Get aggregated statistics</li>
          <li><code>GET /api/programs</code> - Get all programs</li>
          <li><code>GET /api/scrape</code> - Trigger a new scrape</li>
        </ul>
        <div id="stats" class="stats">
          <p class="loading">Loading statistics...</p>
        </div>
        <script>
          fetch('/api/stats')
            .then(r => r.json())
            .then(data => {
              document.getElementById('stats').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(e => {
              document.getElementById('stats').innerHTML = '<p class="loading">Error loading stats</p>';
            });
        </script>
      </body>
      </html>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`\n🐛 Bug Bounty API Server running at http://localhost:${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  if (process.env.NODE_ENV === 'production') {
    console.log('✓ Production mode - Security headers enabled');
  }
  console.log('');
});
