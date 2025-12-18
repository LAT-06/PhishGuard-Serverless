# PhishGuard - Serverless Phishing Link Scanner

A local development environment for a phishing link detection system with Flask backend and Vue.js frontend.

## Project Structure

```
serverless-phish-guard/
├── backend/              # Flask API server
├── frontend/             # Vue.js single page application
├── data/                 # Local file-based cache
├── .gitignore
├── README.md
└── run_local.sh          # Development startup script
```

## Features

- URL validation and phishing detection
- Risk scoring system with suspicious pattern detection
- File-based caching for scan results
- RESTful API with health checks
- Modern Vue.js frontend with real-time scanning
- Comprehensive test suite

## Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:

   ```bash
   cd backend
   ```

2. Create a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Create environment file:

   ```bash
   cp .env.example .env
   ```

5. Run the backend:
   ```bash
   python app.py
   ```

Backend will run on http://localhost:5000

### Frontend Setup

1. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

Frontend will run on http://localhost:3000

### Quick Start with Script

Use the provided script to start both servers:

```bash
chmod +x run_local.sh
./run_local.sh
```

## API Endpoints

### Health Check

```
GET /health
```

### Scan URL

```
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Get Cache Statistics

```
GET /api/cache
```

### Clear Cache

```
DELETE /api/cache
```

## Risk Scoring System

The scanner analyzes URLs for suspicious patterns:

- Suspicious keywords (login, verify, account, etc.)
- Excessive hyphens in domain
- IP addresses instead of domain names
- Unusually long URLs
- Excessive subdomains

Risk levels:

- Low: 0-29 points
- Medium: 30-59 points
- High: 60-100 points

## Testing

Run backend tests:

```bash
cd backend
pytest
```

Run tests with coverage:

```bash
pytest --cov=. --cov-report=html
```

## Development Notes

- Cache is stored in `data/cache.json`
- Backend uses Flask with CORS enabled for local development
- Frontend uses Vite for fast development server
- All configuration is managed through environment variables

## Security Considerations

- This is a development version for local testing
- Do not use the default SECRET_KEY in production
- Implement proper authentication for production deployment
- Consider rate limiting for API endpoints
- Validate and sanitize all user inputs

## Future Enhancements

- Integration with external threat intelligence APIs
- Machine learning-based detection
- Real-time URL monitoring
- User authentication and history tracking
- Deployment to serverless platforms (AWS Lambda, etc.)

## License

This project is for educational and development purposes.
