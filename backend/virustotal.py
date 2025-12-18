import requests
import time
import base64
import logging
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class VirusTotalAPIError(Exception):
    pass


class VirusTotalRateLimitError(Exception):
    pass


class VirusTotalScanner:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        self.timeout = 30
        self.max_retries = 3
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = f"{self.BASE_URL}/{endpoint}"
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('headers', self.headers)
        
        for attempt in range(self.max_retries):
            try:
                response = requests.request(method, url, **kwargs)
                
                if response.status_code == 429:
                    wait_time = (2 ** attempt) * 2
                    logger.warning(f"Rate limit hit, waiting {wait_time} seconds")
                    time.sleep(wait_time)
                    continue
                
                return response
            
            except requests.exceptions.Timeout:
                if attempt == self.max_retries - 1:
                    raise VirusTotalAPIError("Request timeout")
                wait_time = 2 ** attempt
                time.sleep(wait_time)
            
            except requests.exceptions.RequestException as e:
                raise VirusTotalAPIError(f"Network error: {str(e)}")
        
        raise VirusTotalRateLimitError("Rate limit exceeded after retries")
    
    def _validate_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False
    
    def _url_to_id(self, url: str) -> str:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id
    
    def _submit_url(self, url: str) -> str:
        logger.info(f"Submitting URL to VirusTotal: {url}")
        
        response = self._make_request(
            'POST',
            'urls',
            data={'url': url}
        )
        
        if response.status_code == 401:
            raise VirusTotalAPIError("Invalid API key")
        
        if response.status_code != 200:
            raise VirusTotalAPIError(f"Failed to submit URL: {response.status_code}")
        
        data = response.json()
        analysis_id = data['data']['id']
        logger.info(f"URL submitted, analysis ID: {analysis_id}")
        return analysis_id
    
    def _get_analysis_results(self, url_id: str) -> dict:
        logger.info(f"Retrieving analysis results for: {url_id}")
        
        response = self._make_request(
            'GET',
            f'urls/{url_id}'
        )
        
        if response.status_code == 404:
            raise VirusTotalAPIError("URL not found in VirusTotal database")
        
        if response.status_code != 200:
            raise VirusTotalAPIError(f"Failed to get analysis: {response.status_code}")
        
        return response.json()
    
    def _parse_results(self, vt_response: dict, original_url: str) -> Dict:
        data = vt_response.get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        
        total_engines = malicious + suspicious + undetected + harmless
        
        if total_engines == 0:
            risk_score = 0
            status = "unknown"
        else:
            detection_rate = (malicious + suspicious) / total_engines
            risk_score = int(detection_rate * 100)
            
            if malicious > 0:
                status = "malicious"
            elif suspicious > 0:
                status = "suspicious"
            else:
                status = "safe"
        
        categories = []
        last_analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in last_analysis_results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                engine_result = result.get('result', 'unknown')
                if engine_result and engine_result not in categories:
                    categories.append(engine_result)
        
        scan_date = attributes.get('last_analysis_date')
        if scan_date:
            scan_date = datetime.fromtimestamp(scan_date).isoformat()
        else:
            scan_date = datetime.utcnow().isoformat()
        
        return {
            'url': original_url,
            'risk_score': risk_score,
            'status': status,
            'detections': {
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': undetected,
                'total_engines': total_engines
            },
            'categories': categories[:10],
            'scan_date': scan_date
        }
    
    def scan_url(self, url: str) -> Dict:
        if not self._validate_url(url):
            raise ValueError(f"Invalid URL format: {url}")
        
        logger.info(f"Starting VirusTotal scan for: {url}")
        
        try:
            analysis_id = self._submit_url(url)
            
            logger.info("Waiting 5 seconds for VirusTotal processing")
            time.sleep(5)
            
            url_id = self._url_to_id(url)
            vt_response = self._get_analysis_results(url_id)
            
            result = self._parse_results(vt_response, url)
            logger.info(f"Scan complete. Status: {result['status']}, Risk: {result['risk_score']}")
            
            return result
        
        except VirusTotalRateLimitError as e:
            logger.error(f"Rate limit error: {str(e)}")
            raise
        
        except VirusTotalAPIError as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            raise
        
        except Exception as e:
            logger.error(f"Unexpected error during scan: {str(e)}")
            raise VirusTotalAPIError(f"Scan failed: {str(e)}")
