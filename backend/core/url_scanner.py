import re
import logging
import base64
import time
import requests
from urllib.parse import urlparse
from sqlalchemy.orm import Session

import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings
from backend.database.models import Blacklist, Whitelist

logger = logging.getLogger(__name__)

# Bộ nhớ tạm (Cache thời gian) để lưu thời điểm quét URL gần nhất qua VirusTotal (Cooldown 10 phút)
_url_scan_cache = {}
VIRUSTOTAL_COOLDOWN_SECONDS = 600

# Quản lý Rate Limit chuẩn 4 requests/min cho VirusTotal Free tier
_vt_request_timestamps = []
MAX_VT_REQUESTS_PER_MINUTE = 4


def can_make_vt_request() -> bool:
    global _vt_request_timestamps
    now = time.time()
    _vt_request_timestamps = [t for t in _vt_request_timestamps if now - t < 60]
    return len(_vt_request_timestamps) < MAX_VT_REQUESTS_PER_MINUTE


def record_vt_request():
    global _vt_request_timestamps
    _vt_request_timestamps.append(time.time())


def extract_domain(url: str) -> str:
    """Trích xuất domain từ URL"""
    try:
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        domain = parsed.netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        return domain
    except Exception:
        return url.lower()


def check_blacklist(db: Session, url: str) -> dict:
    domain = extract_domain(url)
    blacklisted = db.query(Blacklist).filter(
        Blacklist.value.in_([url, domain])
    ).first()

    if blacklisted:
        return {
            'is_blacklisted': True,
            'match_value': blacklisted.value,
            'reason': blacklisted.reason or 'Trong danh sách đen'
        }
    return {'is_blacklisted': False}


def check_whitelist(db: Session, url: str) -> bool:
    domain = extract_domain(url)
    result = db.query(Whitelist).filter(
        Whitelist.value.in_([url, domain])
    ).first()
    return result is not None


def check_virustotal(url: str) -> dict:
    """Gửi URL đến VirusTotal API v3 có kiểm soát Rate Limit & Cache"""
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key chưa được cấu hình")
        return {'vt_checked': False, 'vt_malicious': 0, 'vt_total': 0}

    current_time = time.time()

    # 1. Kiểm tra cache cá nhân của URL (Tránh quét lại trùng lặp trong 10 phút)
    if url in _url_scan_cache:
        if current_time - _url_scan_cache[url] < VIRUSTOTAL_COOLDOWN_SECONDS:
            logger.debug(f"⏳ URL {url} nằm trong cache VT, bỏ qua gọi API.")
            return {'vt_checked': True, 'vt_cached': True, 'vt_malicious': 0, 'vt_total': 0}

    # 2. Kiểm tra giới hạn 4 requests/phút
    if not can_make_vt_request():
        logger.warning(f"⚠️ Đã đạt giới hạn 4 lookups/min của VirusTotal. Bỏ qua quét URL: {url}")
        return {'vt_checked': False, 'vt_limited': True, 'vt_malicious': 0, 'vt_total': 0}

    try:
        record_vt_request()
        _url_scan_cache[url] = current_time

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if response.status_code == 200:
            scan_id = response.json().get('data', {}).get('id', '')
            time.sleep(2)  # Chờ phân tích ngắn

            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers,
                timeout=10
            )

            if result_response.status_code == 200:
                stats = result_response.json().get('data', {}).get('attributes', {}).get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())

                return {
                    'vt_checked': True,
                    'vt_malicious': malicious + suspicious,
                    'vt_total': total,
                    'vt_clean': stats.get('undetected', 0),
                    'vt_permalink': f"https://www.virustotal.com/gui/url/{url_id}"
                }

        return {'vt_checked': False, 'vt_malicious': 0, 'vt_total': 0}

    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return {'vt_checked': False, 'vt_malicious': 0, 'vt_total': 0}


def analyze_url_features(url: str) -> dict:
    features = {
        'has_ip': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        'is_shortened': bool(re.search(r'bit\.ly|tinyurl|t\.co|goo\.gl|shorturl|ow\.ly', url, re.I)),
        'has_suspicious_keywords': bool(re.search(
            r'login|verify|account|update|secure|banking|paypal|credential|confirm|reset|password',
            url, re.I
        )),
        'has_many_subdomains': url.count('.') > 4,
        'has_at_symbol': '@' in url,
        'is_http_not_https': url.lower().startswith('http://') and not url.lower().startswith('https://'),
        'has_double_slash': '//' in url[8:],
        'url_length': len(url),
        'is_very_long': len(url) > 150,
    }
    features['suspicious_score'] = sum([
        features['has_ip'], features['is_shortened'], features['has_suspicious_keywords'],
        features['has_many_subdomains'], features['has_at_symbol'],
        features['is_http_not_https'], features['is_very_long']
    ])
    return features


def scan_urls(db: Session, urls: list[str], use_virustotal: bool = True) -> dict:
    if not urls:
        return {'total': 0, 'malicious': 0, 'safe': 0, 'details': []}

    results = []
    malicious_count = 0

    for url in urls[:10]:
        url_result = {
            'url': url,
            'domain': extract_domain(url),
            'is_malicious': False,
            'threat_source': None,
            'details': {}
        }

        if check_whitelist(db, url):
            url_result['threat_source'] = 'whitelist_safe'
            results.append(url_result)
            continue

        bl_result = check_blacklist(db, url)
        if bl_result['is_blacklisted']:
            url_result['is_malicious'] = True
            url_result['threat_source'] = 'blacklist'
            url_result['details'] = bl_result
            malicious_count += 1
            results.append(url_result)
            continue

        features = analyze_url_features(url)
        url_result['details']['features'] = features

        if use_virustotal and settings.VIRUSTOTAL_API_KEY:
            vt_result = check_virustotal(url)
            url_result['details']['virustotal'] = vt_result

            if vt_result.get('vt_checked') and vt_result.get('vt_malicious', 0) > 0:
                url_result['is_malicious'] = True
                url_result['threat_source'] = 'virustotal'
                malicious_count += 1
                results.append(url_result)
                continue

        if features['suspicious_score'] >= 3:
            url_result['is_malicious'] = True
            url_result['threat_source'] = 'heuristic'
            malicious_count += 1

        results.append(url_result)

    return {
        'total': len(results),
        'malicious': malicious_count,
        'safe': len(results) - malicious_count,
        'details': results
    }
