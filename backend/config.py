import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 5000))
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    CACHE_FILE = os.getenv('CACHE_FILE', os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 
        'data', 
        'cache.json'
    ))
    CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))
    
    LOG_FILE = os.getenv('LOG_FILE', os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'logs',
        'app.log'
    ))
    
    @classmethod
    def validate(cls):
        if not cls.VIRUSTOTAL_API_KEY:
            raise ValueError(
                "VIRUSTOTAL_API_KEY is required. "
                "Please set it in your .env file. "
                "Get your API key from https://www.virustotal.com/gui/my-apikey"
            )
