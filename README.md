# PhishGuard-Serverless

A comprehensive phishing detection and prevention system with Flask backend and Vue 3 frontend. Features VirusTotal integration, Visual Sandbox previews, domain intelligence, and AWS-ready serverless architecture.

## Features

### Core Security Features

- **VirusTotal Integration**: Real-time scanning with 90+ security engines
- **Visual Sandbox**: Safe website preview using headless browsers (Chromium/Firefox)
- **Domain Intelligence**: WHOIS data, registrar info, IP address resolution
- **SSRF Protection**: Blocks localhost and private IP scanning attempts
- **Rate Limiting**: 5 requests/minute per IP for scan endpoint
- **Smart Risk Scoring**: Threshold-based detection (2+ malicious flags = 90+ risk score)

### Technical Features

- **Cloud-Ready Cache**: Strategy Pattern with File/DynamoDB support
- **Modern Frontend**: Vue 3 Composition API with dark theme
- **Environment Config**: Multi-environment deployment support
- **Comprehensive Testing**: 95% code coverage with pytest
- **AWS Serverless Ready**: Lambda-compatible architecture

## Project Structure

```
PhishGuard-Serverless/
├── backend/                    # Flask API server
│   ├── app.py                 # Main application
│   ├── virustotal.py          # VirusTotal API integration
│   ├── screenshot.py          # Visual Sandbox (Selenium)
│   ├── infrastructure.py      # Domain WHOIS/IP lookup
│   ├── cache.py               # Strategy Pattern cache (File/DynamoDB)
│   ├── validators.py          # URL validation & SSRF protection
│   ├── config.py              # Configuration management
│   └── requirements.txt       # Python dependencies
├── frontend/                   # Vue 3 SPA
│   ├── src/
│   │   ├── components/
│   │   │   └── Scanner.vue    # Main scanner component
│   │   └── App.vue
│   ├── .env                   # Environment variables
│   └── package.json
├── tests/                      # Pytest test suite
├── data/                       # Local cache storage
├── logs/                       # Application logs
├── note.txt                    # Development documentation
└── README.md

```

## Prerequisites

- **Python 3.8+**
- **Node.js 16+**
- **Chrome/Chromium** (for Visual Sandbox)
- **Firefox** (for Visual Sandbox)
- **VirusTotal API Key** (free tier: 4 requests/minute)

## Quick Start

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env

# Add your VirusTotal API key to .env
# VIRUSTOTAL_API_KEY=your_key_here

# Run server
python app.py
```

Backend runs on: `http://localhost:5000`

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Run development server
npm run dev
```

Frontend runs on: `http://localhost:5173`

### 3. Access Application

Open browser: `http://localhost:5173`

## API Endpoints

### Scan URL

```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "risk_score": 0,
    "status": "safe",
    "detections": {
      "malicious": 0,
      "suspicious": 0,
      "undetected": 90,
      "total_engines": 90
    },
    "infrastructure": {
      "domain": "example.com",
      "creation_date": "1995-08-14",
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "ip_address": "93.184.216.34"
    },
    "categories": [],
    "scanned_at": "2025-12-22T10:30:00.000Z",
    "cached": false
  }
}
```

### Capture Screenshot

```http
POST /api/screenshot
Content-Type: application/json

{
  "url": "https://example.com",
  "browser": "chrome"  // "chrome", "firefox", or "both"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "success": true,
    "screenshot": "base64_encoded_png_data",
    "browser": "chrome",
    "format": "png"
  }
}
```

### Health Check

```http
GET /api/health
```

### Cache Management

```http
DELETE /api/cache?confirm=true  # Clear all cache
POST /api/cache/clean            # Clean expired entries
```

## Risk Scoring System

### Threshold-Based Detection

- **2+ malicious detections**: Score 90-100 (Malicious)
- **1 malicious OR 2+ suspicious**: Score 75 (Suspicious)
- **1 suspicious**: Score 40 (Warning)
- **0 detections**: Score 0 (Safe)

### Frontend Classification

- **Malicious (Red)**: Any URL with 1+ malicious detection
- **Suspicious (Orange)**: 1+ suspicious detection
- **Safe (Green)**: 0 detections

**Security-First Approach**: Even 1 malicious detection triggers red warning.

## Configuration

### Backend (.env)

```bash
# Required
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional
HOST=0.0.0.0
PORT=5000
DEBUG=False
CACHE_FILE=data/cache.json
CACHE_TTL=3600
LOG_FILE=logs/app.log

# AWS (for production)
AWS_REGION=us-east-1
DYNAMODB_TABLE_NAME=phishguard-cache
```

### Frontend (.env)

```bash
# Development
VITE_API_URL=http://localhost:5000/api

# Production
# VITE_API_URL=https://api.yourdomain.com/api
```

## Testing

```bash
cd backend

# Run all tests
pytest

# With coverage report
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_virustotal.py
```

**Current Coverage**: 95% (57/58 tests passing)

## Visual Sandbox

The Visual Sandbox captures screenshots using headless browsers without executing JavaScript in your session.

**Features:**

- Automatic browser detection (Chromium/Firefox)
- Safe preview of suspicious URLs
- No cookies or user data exposed
- 3-5 second capture time
- Click to enlarge fullscreen view

**Security:**

- Sandboxed execution
- SSRF protection (blocks localhost/private IPs)
- Rate limited (3 requests/minute)
- No user interaction with target site

## Domain Intelligence

**Gathered Data:**

- Domain creation date
- Registrar information
- IP address resolution
- WHOIS lookup

**Security Indicators:**

- New domains (<30 days) are high-risk
- Privacy-protected WHOIS may indicate hiding
- IP address instead of domain is suspicious

## SSRF Protection

**Blocked Targets:**

- Localhost (127.0.0.1, localhost)
- Private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Link-local addresses (169.254.x.x)
- Invalid protocols (only http/https allowed)

## AWS Deployment

### Architecture

- **AWS Lambda**: Serverless functions
- **API Gateway**: REST API endpoint
- **DynamoDB**: Distributed cache
- **S3 + CloudFront**: Static frontend hosting

### Cache Strategy

The cache system automatically detects environment:

- **Local**: File-based cache with JSON
- **AWS**: DynamoDB with boto3

Set `AWS_LAMBDA_FUNCTION_NAME` environment variable to enable DynamoDB mode.

## Performance

- **VirusTotal Scan**: 5-10 seconds (depends on API)
- **Screenshot Capture**: 3-5 seconds per browser
- **Cache Hit**: <100ms response time
- **Domain Lookup**: 1-3 seconds (WHOIS)

## Rate Limits

- **Scan Endpoint**: 5 requests/minute per IP
- **Screenshot Endpoint**: 3 requests/minute per IP
- **VirusTotal API**: 4 requests/minute (free tier)

## Security Best Practices

1. **Never expose API keys** in frontend code
2. **Use environment variables** for sensitive config
3. **Enable rate limiting** in production
4. **Validate all inputs** server-side
5. **Use HTTPS** for production deployment
6. **Implement authentication** for public deployments
7. **Monitor logs** for suspicious activity
8. **Keep dependencies updated** regularly

## Technology Stack

### Backend

- Flask 3.0.0
- flask-cors 4.0.0
- flask-limiter 3.5.0
- requests 2.31.0
- selenium 4.16.0
- python-whois 0.8.0
- boto3 1.34.0 (AWS)
- pytest 7.4.3

### Frontend

- Vue 3.4.0
- Vite 5.0.0
- axios 1.6.0

## Development Workflow

1. **Read `note.txt`** before making changes
2. **Update `note.txt`** after implementing features
3. **Run tests** before committing
4. **Check coverage** to maintain 90%+
5. **Update README** when adding features

## Troubleshooting

### Backend Issues

**Port already in use:**

```bash
lsof -ti:5000 | xargs kill -9
```

**Missing dependencies:**

```bash
pip install -r requirements.txt
```

**VirusTotal errors:**

- Check API key in `.env`
- Verify rate limits (4 req/min free tier)
- Check logs in `logs/app.log`

### Frontend Issues

**Module not found:**

```bash
rm -rf node_modules package-lock.json
npm install
```

**API connection failed:**

- Verify backend is running on port 5000
- Check CORS configuration
- Verify `VITE_API_URL` in `.env`

### Screenshot Issues

**WebDriver errors:**

```bash
# Install browsers
sudo apt install chromium-browser firefox

# Update drivers
pip install --upgrade selenium webdriver-manager
```

## Contributing

This project follows a strict documentation-first workflow:

1. Read `note.txt` completely
2. Implement changes
3. Update `note.txt` with detailed documentation
4. Run tests and update coverage
5. Update README if needed

## License

Educational and development purposes.

## Support

For issues and questions, check `note.txt` for detailed technical documentation.

---

**Built with security-first principles** | **Cloud-ready architecture** | **95% test coverage**
