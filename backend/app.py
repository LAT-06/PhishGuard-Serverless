from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from config import Config
from cache import CacheManager
from virustotal import VirusTotalScanner, VirusTotalAPIError, VirusTotalRateLimitError
from validators import is_safe_url, validate_url_format
from infrastructure import get_domain_info
from screenshot import ScreenshotCapture
from threat_intelligence import ThreatIntelligence

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def setup_logging():
    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        Config.LOG_FILE, maxBytes=10485760, backupCount=10
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
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
    screenshot_capture = ScreenshotCapture(timeout=10, window_size=(1920, 1080))
    threat_intel = ThreatIntelligence()
    logger.info("Application initialized successfully")
except ValueError as e:
    logger.error(f"Configuration error: {str(e)}")
    raise


@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    logger.debug("Health check requested")

    try:
        cache_size = cache_manager.get_cache_size()
        api_configured = bool(Config.VIRUSTOTAL_API_KEY)

        return jsonify(
            {
                "status": "healthy",
                "cache_size": cache_size,
                "api_configured": api_configured,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per minute")
def scan_url():
    logger.info("Scan request received")

    try:
        data = request.get_json()

        if not data or "url" not in data:
            logger.warning("Scan request missing URL")
            return jsonify(
                {"success": False, "error": "URL is required in request body"}
            ), 400

        url = data["url"].strip()
        logger.info(f"Scanning URL: {url}")

        # Basic format validation
        is_valid_format, format_error = validate_url_format(url)
        if not is_valid_format:
            logger.warning(f"Invalid URL format: {url} - {format_error}")
            return jsonify({"success": False, "error": format_error}), 400

        # SSRF protection
        is_safe, safety_error = is_safe_url(url)
        if not is_safe:
            logger.warning(f"Unsafe URL detected: {url} - {safety_error}")
            return jsonify({"success": False, "error": safety_error}), 400

        url_hash = cache_manager.generate_url_hash(url)
        logger.debug(f"URL hash: {url_hash}")

        cached_entry = cache_manager.get_from_cache(url_hash)

        if cached_entry:
            logger.info(f"Cache hit for URL: {url}")
            result = cached_entry["result"]
            result["cached"] = True
            return jsonify({"success": True, "data": result})

        logger.info(f"Cache miss for URL: {url}, calling VirusTotal API")

        try:
            scan_result = vt_scanner.scan_url(url)
            
            # Infrastructure analysis
            try:
                logger.info(f"Fetching domain info for URL: {url}")
                infra_result = get_domain_info(url)
                scan_result["infrastructure"] = infra_result
            except Exception as infra_e:
                logger.error(f"Error fetching domain info: {str(infra_e)}")
                scan_result["infrastructure"] = {
                    "error": "Could not fetch infrastructure data"
                }
            
            # Threat Intelligence analysis
            try:
                logger.info(f"Running threat intelligence analysis for URL: {url}")
                threat_analysis = threat_intel.analyze_url(
                    url, 
                    scan_result.get("infrastructure")
                )
                scan_result["threat_intelligence"] = threat_analysis
                
                # Adjust final risk score based on threat intelligence
                original_risk = scan_result.get("risk_score", 0)
                threat_score = threat_analysis.get("threat_score", 0)
                
                # Combined score: max of VirusTotal and Threat Intelligence
                combined_score = max(original_risk, threat_score)
                scan_result["risk_score"] = combined_score
                scan_result["original_vt_score"] = original_risk
                
                # Update status based on combined score
                if combined_score >= 90:
                    scan_result["status"] = "malicious"
                elif combined_score >= 75:
                    scan_result["status"] = "suspicious"
                elif combined_score >= 40:
                    scan_result["status"] = "warning"
                
                logger.info(f"Threat intelligence: Original score {original_risk}, Threat score {threat_score}, Final score {combined_score}")
                
            except Exception as threat_e:
                logger.error(f"Error in threat intelligence analysis: {str(threat_e)}")
                scan_result["threat_intelligence"] = {
                    "error": "Could not analyze threat intelligence"
                }

            scan_result["cached"] = False
            scan_result["scanned_at"] = datetime.utcnow().isoformat()

            cache_manager.save_to_cache(url_hash, scan_result)
            logger.info(f"Scan completed and cached for URL: {url}")

            return jsonify({"success": True, "data": scan_result})

        except ValueError as e:
            logger.warning(f"Invalid URL: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 400

        except VirusTotalRateLimitError as e:
            logger.error(f"Rate limit error: {str(e)}")
            return jsonify(
                {
                    "success": False,
                    "error": "VirusTotal API rate limit exceeded. Please try again later.",
                }
            ), 429

        except VirusTotalAPIError as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return jsonify(
                {"success": False, "error": f"VirusTotal API error: {str(e)}"}
            ), 503

    except Exception as e:
        logger.error(f"Unexpected error in scan_url: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "An unexpected error occurred"}), 500


@app.route("/api/cache", methods=["DELETE"])
def clear_cache():
    logger.info("Cache clear request received")

    try:
        confirm = request.args.get("confirm", "").lower()

        if confirm != "true":
            return jsonify(
                {
                    "success": False,
                    "error": "Confirmation required. Add ?confirm=true to URL",
                }
            ), 400

        count = cache_manager.clear_all()
        logger.info(f"Cache cleared, {count} entries removed")

        return jsonify(
            {
                "success": True,
                "message": f"Cache cleared successfully",
                "deleted_count": count,
            }
        )

    except Exception as e:
        logger.error(f"Error clearing cache: {str(e)}")
        return jsonify({"success": False, "error": "Failed to clear cache"}), 500


@app.route("/api/cache/clean", methods=["POST"])
def clean_expired():
    logger.info("Cache cleanup request received")

    try:
        count = cache_manager.clean_expired_entries()
        logger.info(f"Cleaned {count} expired cache entries")

        return jsonify(
            {
                "success": True,
                "message": f"Cleaned {count} expired entries",
                "cleaned_count": count,
            }
        )

    except Exception as e:
        logger.error(f"Error cleaning cache: {str(e)}")
        return jsonify({"success": False, "error": "Failed to clean cache"}), 500


@app.route("/api/screenshot", methods=["POST"])
@limiter.limit("3 per minute")
def capture_screenshot():
    """Capture screenshot of URL using headless browsers."""
    logger.info("Screenshot request received")

    try:
        data = request.get_json()

        if not data or "url" not in data:
            logger.warning("Screenshot request missing URL")
            return jsonify(
                {"success": False, "error": "URL is required in request body"}
            ), 400

        url = data["url"].strip()
        browser = data.get("browser", "both").lower()  # "chrome", "firefox", or "both"
        logger.info(f"Capturing screenshot of: {url} (browser: {browser})")

        # Basic validation
        is_valid_format, format_error = validate_url_format(url)
        if not is_valid_format:
            logger.warning(f"Invalid URL format: {url} - {format_error}")
            return jsonify({"success": False, "error": format_error}), 400

        # SSRF protection
        is_safe, safety_error = is_safe_url(url)
        if not is_safe:
            logger.warning(f"Unsafe URL detected: {url} - {safety_error}")
            return jsonify({"success": False, "error": safety_error}), 400

        # Capture screenshots
        if browser == "both":
            result = screenshot_capture.capture_both_browsers(url)
            logger.info(f"Screenshots captured with both browsers for: {url}")
        elif browser in ["chrome", "firefox"]:
            result = screenshot_capture.capture_screenshot(url, browser=browser)
            logger.info(f"Screenshot captured with {browser} for: {url}")
        else:
            return jsonify(
                {"success": False, "error": "Invalid browser. Use 'chrome', 'firefox', or 'both'"}
            ), 400

        return jsonify({"success": True, "data": result})

    except Exception as e:
        logger.error(f"Unexpected error in capture_screenshot: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "An unexpected error occurred"}), 500


if __name__ == "__main__":
    logger.info(f"Starting Flask server on {Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
