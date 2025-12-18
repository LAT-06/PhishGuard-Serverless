from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from config import Config
from cache import CacheManager
from virustotal import VirusTotalScanner, VirusTotalAPIError, VirusTotalRateLimitError

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)


def setup_logging():
    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=10485760,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    file_handler.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    console_handler.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    app.logger.info("Logging initialized")


setup_logging()
logger = logging.getLogger(__name__)

try:
    Config.validate()
    cache_manager = CacheManager(Config.CACHE_FILE, Config.CACHE_TTL)
    vt_scanner = VirusTotalScanner(Config.VIRUSTOTAL_API_KEY)
    logger.info("Application initialized successfully")
except ValueError as e:
    logger.error(f"Configuration error: {str(e)}")
    raise


@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    logger.debug("Health check requested")
    
    try:
        cache_size = cache_manager.get_cache_size()
        api_configured = bool(Config.VIRUSTOTAL_API_KEY)
        
        return jsonify({
            'status': 'healthy',
            'cache_size': cache_size,
            'api_configured': api_configured,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/api/scan', methods=['POST'])
def scan_url():
    logger.info("Scan request received")
    
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            logger.warning("Scan request missing URL")
            return jsonify({
                'success': False,
                'error': 'URL is required in request body'
            }), 400
        
        url = data['url'].strip()
        logger.info(f"Scanning URL: {url}")
        
        if not url.startswith(('http://', 'https://')):
            logger.warning(f"Invalid URL format: {url}")
            return jsonify({
                'success': False,
                'error': 'URL must start with http:// or https://'
            }), 400
        
        url_hash = cache_manager.generate_url_hash(url)
        logger.debug(f"URL hash: {url_hash}")
        
        cached_entry = cache_manager.get_from_cache(url_hash)
        
        if cached_entry:
            logger.info(f"Cache hit for URL: {url}")
            result = cached_entry['result']
            result['cached'] = True
            return jsonify({
                'success': True,
                'data': result
            })
        
        logger.info(f"Cache miss for URL: {url}, calling VirusTotal API")
        
        try:
            scan_result = vt_scanner.scan_url(url)
            scan_result['cached'] = False
            scan_result['scanned_at'] = datetime.utcnow().isoformat()
            
            cache_manager.save_to_cache(url_hash, scan_result)
            logger.info(f"Scan completed and cached for URL: {url}")
            
            return jsonify({
                'success': True,
                'data': scan_result
            })
        
        except ValueError as e:
            logger.warning(f"Invalid URL: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        except VirusTotalRateLimitError as e:
            logger.error(f"Rate limit error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'VirusTotal API rate limit exceeded. Please try again later.'
            }), 429
        
        except VirusTotalAPIError as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'VirusTotal API error: {str(e)}'
            }), 503
    
    except Exception as e:
        logger.error(f"Unexpected error in scan_url: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@app.route('/api/cache', methods=['DELETE'])
def clear_cache():
    logger.info("Cache clear request received")
    
    try:
        confirm = request.args.get('confirm', '').lower()
        
        if confirm != 'true':
            return jsonify({
                'success': False,
                'error': 'Confirmation required. Add ?confirm=true to URL'
            }), 400
        
        count = cache_manager.clear_all()
        logger.info(f"Cache cleared, {count} entries removed")
        
        return jsonify({
            'success': True,
            'message': f'Cache cleared successfully',
            'deleted_count': count
        })
    
    except Exception as e:
        logger.error(f"Error clearing cache: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to clear cache'
        }), 500


@app.route('/api/cache/clean', methods=['POST'])
def clean_expired():
    logger.info("Cache cleanup request received")
    
    try:
        count = cache_manager.clean_expired_entries()
        logger.info(f"Cleaned {count} expired cache entries")
        
        return jsonify({
            'success': True,
            'message': f'Cleaned {count} expired entries',
            'cleaned_count': count
        })
    
    except Exception as e:
        logger.error(f"Error cleaning cache: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to clean cache'
        }), 500


if __name__ == '__main__':
    logger.info(f"Starting Flask server on {Config.HOST}:{Config.PORT}")
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )
