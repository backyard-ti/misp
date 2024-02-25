#credit to https://github.com/kraven-security/python-threat-hunting-tools/blob/main/misp/misp-to-crowdstrike.py for original idea and code

import logging
from datetime import datetime, timedelta
from validators import ip_address
from pymisp import PyMISP
from falconpy import IOC
from config import config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MISP Configuration
MISP_URL = config['MISP_URL']
MISP_KEY = config['MISP_KEY']
MISP_VERIFYCERT = config['MISP_VERIFYCERT']

# CrowdStrike Configuration
CS_CLIENT_ID = config['CS_CLIENT_ID']
CS_CLIENT_SECRET = config['CS_CLIENT_SECRET']

def get_misp_attributes(misp_url, misp_key, misp_verifycert):
    """
    Fetches attributes from MISP and classifies them by type.
    
    :param misp_url: URL of the MISP instance.
    :param misp_key: Auth key for the MISP instance.
    :param misp_verifycert: SSL certificate verification.
    :return: Dict of classified attributes.
    """
    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert, debug=False)
        attributes = misp.search(controller='attributes', to_ids=1, pythonify=True, publish_timestamp='89d')
    except Exception as e:
        logging.error(f"Failed to fetch MISP attributes: {e}")
        return {}

    classified_attributes = {
        "ipv4": [], "ipv6": [], "domain": [], "url": [], "hostname": [],
        "sha256": [], "md5": [], "sha1": []
    }

    for attr in attributes:
        try:
            if attr.type == "ip-dst":
                if ip_address.ipv4(attr.value):
                    classified_attributes['ipv4'].append(attr.value)
                elif ip_address.ipv6(attr.value):
                    classified_attributes['ipv6'].append(attr.value)
            elif attr.type in ["domain", "hostname"]:
                classified_attributes['domain'].append(attr.value)
            elif attr.type == "url":
                classified_attributes['url'].append(attr.value)
            elif attr.type == "sha256":
                classified_attributes['sha256'].append(attr.value)
            elif attr.type == "md5":
                classified_attributes['md5'].append(attr.value)
            elif attr.type == "sha1":
                classified_attributes['sha1'].append(attr.value)
        except Exception as e:
            logging.warning(f"Error processing attribute {attr}: {e}")

    return classified_attributes

def upload_iocs(iocs_to_upload):
    """
    Uploads classified IOCs to CrowdStrike Falcon.

    :param iocs_to_upload: Dict of IOCs to upload.
    """
    try:
        falcon = IOC(client_id=CS_CLIENT_ID, client_secret=CS_CLIENT_SECRET)
    except Exception as e:
        logging.error(f"Failed to initialize Falcon API client: {e}")
        return

    ioc_platforms = ["Windows", "Mac", "Linux"]
    now = datetime.now() + timedelta(days=90)
    ioc_expiry_date = now.isoformat() + "Z"
    uploaded_iocs, failed_iocs = [], []

    for ioc_type, iocs in iocs_to_upload.items():
        for ioc in iocs:
            try:
                response = falcon.indicator_create(
                    action="add", value=ioc, type=ioc_type, severity="high", platforms=ioc_platforms,
                    applied_globally=True, retrodetects=True, description="MISP IOCs",
                    expiration=ioc_expiry_date
                )
                if response["status_code"] == 201:
                    uploaded_iocs.append(ioc)
                else:
                    logging.error(f"Failed to upload {ioc}: {response}")
                    failed_iocs.append(ioc)
            except Exception as e:
                logging.error(f"Error uploading IOC {ioc}: {e}")
                failed_iocs.append(ioc)

    logging.info(f"Uploaded {len(uploaded_iocs)} new IOCs to CrowdStrike Falcon")
    logging.info(f"Failed to upload {len(failed_iocs)} IOCs to CrowdStrike Falcon")

    # Optionally, fetch and log the new total of IOCs in CrowdStrike for verification

if __name__ == "__main__":
    logging.info("--- Script Start ---")
    indicators = get_misp_attributes(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    if indicators:
        upload_iocs(indicators)
    logging.info("--- Script Complete ---")