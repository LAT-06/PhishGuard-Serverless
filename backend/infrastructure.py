import whois
import socket
from urllib.parse import urlparse
from datetime import datetime


def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        # if no http or https is provided, netloc will be empty
        if not domain:
            domain = url.split("/")[0]

        # get whois info
        w = whois.whois(domain)

        # date parsing
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        creation_date_str = (
            creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown"
        )

        # get ip address
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = "Unknown"

        # get registrar
        registrar = w.registrar if w.registrar else "Unknown"

        return {
            "domain": domain,
            "creation_date": creation_date_str,
            "registrar": registrar,
            "ip_address": ip_address,
        }

    except Exception as e:
        return {"error": str(e)}
