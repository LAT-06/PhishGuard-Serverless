import base64
import logging
import tempfile
import os
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import WebDriverException, TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """
    Captures website screenshots using headless browsers.
    Supports both Chromium-based and Firefox-based browsers.
    """

    def __init__(self, timeout=10, window_size=(1920, 1080)):
        """
        Initialize screenshot capture configuration.
        
        Args:
            timeout: Page load timeout in seconds
            window_size: Browser window size tuple (width, height)
        """
        self.timeout = timeout
        self.window_size = window_size

    def _get_chrome_driver(self):
        """
        Create and configure Chrome headless driver.
        
        Returns:
            webdriver.Chrome: Configured Chrome driver instance
        """
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument(f"--window-size={self.window_size[0]},{self.window_size[1]}")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        # Security options
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-popup-blocking")
        
        try:
            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(self.timeout)
            return driver
        except Exception as e:
            logger.error(f"Failed to initialize Chrome driver: {str(e)}")
            raise

    def _get_firefox_driver(self):
        """
        Create and configure Firefox headless driver.
        
        Returns:
            webdriver.Firefox: Configured Firefox driver instance
        """
        firefox_options = FirefoxOptions()
        firefox_options.add_argument("--headless")
        firefox_options.add_argument("--width=" + str(self.window_size[0]))
        firefox_options.add_argument("--height=" + str(self.window_size[1]))
        firefox_options.set_preference("general.useragent.override", 
                                      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
        
        # Security preferences
        firefox_options.set_preference("dom.webdriver.enabled", False)
        firefox_options.set_preference("useAutomationExtension", False)
        
        try:
            service = FirefoxService(GeckoDriverManager().install())
            driver = webdriver.Firefox(service=service, options=firefox_options)
            driver.set_page_load_timeout(self.timeout)
            return driver
        except Exception as e:
            logger.error(f"Failed to initialize Firefox driver: {str(e)}")
            raise

    def capture_screenshot(self, url, browser="chrome"):
        """
        Capture screenshot of a URL using specified browser.
        
        Args:
            url: Target URL to screenshot
            browser: Browser engine to use ("chrome" or "firefox")
            
        Returns:
            dict: {
                "success": bool,
                "screenshot": str (base64 encoded image),
                "browser": str,
                "error": str (if failed)
            }
        """
        driver = None
        
        try:
            logger.info(f"Capturing screenshot of {url} using {browser}")
            
            # Select and initialize browser driver
            if browser.lower() == "firefox":
                driver = self._get_firefox_driver()
            else:
                driver = self._get_chrome_driver()
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to settle (simple wait)
            driver.implicitly_wait(2)
            
            # Capture screenshot as PNG
            screenshot_binary = driver.get_screenshot_as_png()
            
            # Encode to base64 for JSON transport
            screenshot_base64 = base64.b64encode(screenshot_binary).decode('utf-8')
            
            logger.info(f"Successfully captured screenshot of {url} using {browser}")
            
            return {
                "success": True,
                "screenshot": screenshot_base64,
                "browser": browser,
                "format": "png"
            }
            
        except TimeoutException:
            error_msg = f"Timeout loading {url}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "browser": browser
            }
            
        except WebDriverException as e:
            error_msg = f"WebDriver error: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "browser": browser
            }
            
        except Exception as e:
            error_msg = f"Unexpected error capturing screenshot: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {
                "success": False,
                "error": error_msg,
                "browser": browser
            }
            
        finally:
            # Always close the browser
            if driver:
                try:
                    driver.quit()
                except:
                    pass

    def capture_both_browsers(self, url):
        """
        Capture screenshots using both Chrome and Firefox.
        
        Args:
            url: Target URL to screenshot
            
        Returns:
            dict: {
                "chrome": dict (result from Chrome),
                "firefox": dict (result from Firefox)
            }
        """
        logger.info(f"Capturing screenshots with both browsers for {url}")
        
        chrome_result = self.capture_screenshot(url, browser="chrome")
        firefox_result = self.capture_screenshot(url, browser="firefox")
        
        return {
            "chrome": chrome_result,
            "firefox": firefox_result
        }
