from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import requests
from enum import Enum
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrackerCategory(Enum):
    ANALYTICS = "Analytics"
    ADVERTISING = "Advertising"
    SOCIAL = "Social Media"
    MARKETING = "Marketing"
    SESSION_RECORDING = "Session Recording"
    ESSENTIAL = "Essential"

# Define risk levels separately
CATEGORY_RISK_LEVELS = {
    TrackerCategory.ANALYTICS: 3,
    TrackerCategory.ADVERTISING: 6,
    TrackerCategory.SOCIAL: 7,
    TrackerCategory.MARKETING: 5,
    TrackerCategory.SESSION_RECORDING: 8,
    TrackerCategory.ESSENTIAL: 1
}

@dataclass
class TrackerData:
    name: str
    category: TrackerCategory
    url: str
    detected_on: datetime
    description: str
    risk_level: int  # This would now be calculated using CATEGORY_RISK_LEVELS
    data_collected: Set[str]
    is_essential: bool
    has_consent: bool

    def calculate_risk_level(self) -> int:
        base_risk = CATEGORY_RISK_LEVELS[self.category]
        # Apply any additional modifiers here
        return base_risk

@dataclass
class WebsiteData:
    url: str
    trackers: List[TrackerData]
    privacy_score: int
    privacy_explanation: str
    risk_score: int
    risk_explanation: str
    scan_time: datetime

class Tracker:
    def calculate_risk_level(self) -> int:
        base_risk = self.category.risk_level
        modifiers = {
            'has_privacy_policy': -1,
            'data_anonymization': -1,
            'third_party_sharing': +2,
            'persistent_storage': +1,
            'cross_site_tracking': +2
        }
        
        final_risk = base_risk
        for feature, modifier in modifiers.items():
            if self.has_feature(feature):
                final_risk += modifier
                
        return max(1, min(10, final_risk))  # Keep between 1-10

class Website:
    def __init__(self):
        self.website_data: Dict[str, WebsiteData] = {}
        self.known_trackers = {
            'google-analytics': {
                'category': TrackerCategory.ANALYTICS,
                'description': 'Google Analytics tracking',
                'risk_level': 3,
                'is_essential': False,
                'patterns': [
                    r'google-analytics.com',
                    r'googletagmanager.com',
                    r'gtag',
                    r'ga\(',
                    r'analytics\.js'
                ]
            },
            'facebook': {
                'category': TrackerCategory.SOCIAL,
                'description': 'Facebook tracking and social plugins',
                'risk_level': 6,
                'is_essential': False,
                'patterns': [
                    r'connect\.facebook\.net',
                    r'facebook\.com/plugins',
                    r'fbq\(',
                    r'fb-pixel'
                ]
            },
            'doubleclick': {
                'category': TrackerCategory.ADVERTISING,
                'description': 'Google advertising platform',
                'risk_level': 5,
                'is_essential': False,
                'patterns': [
                    r'doubleclick\.net',
                    r'googleadservices',
                    r'googlesyndication'
                ]
            },
            'amazon-ads': {
                'category': TrackerCategory.ADVERTISING,
                'description': 'Amazon advertising system',
                'risk_level': 5,
                'is_essential': False,
                'patterns': [
                    r'amazon-adsystem\.com',
                    r'advertising\.amazon\.com'
                ]
            }
        }

    def scan_current_page(self, url: str) -> Optional[WebsiteData]:
        try:
            logger.info(f"Starting scan for URL: {url}")
            
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://www.google.com/'
            }

            domain = urlparse(url).netloc.lower()
            known_domains = {
                'amazon.com': self._get_amazon_trackers,
                'www.amazon.com': self._get_amazon_trackers,
                'facebook.com': self._get_facebook_trackers,
                'www.facebook.com': self._get_facebook_trackers
            }

            if domain in known_domains:
                trackers = known_domains[domain](url)
                return self._create_website_data(url, trackers)

            response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            trackers = self._detect_trackers(url, soup)
            
            return self._create_website_data(url, trackers)
                
        except Exception as e:
            logger.error(f"Error scanning page: {str(e)}", exc_info=True)
            raise

    def _detect_trackers(self, url: str, soup: BeautifulSoup) -> List[TrackerData]:
        found_trackers = set()
        unique_trackers = []
        
        try:
            page_content = str(soup).lower()
            
            # Check script tags
            for script in soup.find_all('script'):
                src = script.get('src', '').lower()
                if src:
                    self._check_source_patterns(src, found_trackers, unique_trackers, url)
                if script.string:
                    self._check_content_patterns(script.string.lower(), found_trackers, unique_trackers, url)
            
            # Check link tags
            for link in soup.find_all('link'):
                href = link.get('href', '').lower()
                if href:
                    self._check_source_patterns(href, found_trackers, unique_trackers, url)
            
            # Check full page content
            self._check_content_patterns(page_content, found_trackers, unique_trackers, url)
            
            return unique_trackers
            
        except Exception as e:
            logger.error(f"Error detecting trackers: {str(e)}", exc_info=True)
            return []

    def _check_source_patterns(self, source: str, found_trackers: set, unique_trackers: list, url: str):
        for tracker_id, info in self.known_trackers.items():
            if tracker_id not in found_trackers:
                for pattern in info['patterns']:
                    if re.search(pattern, source, re.I):
                        found_trackers.add(tracker_id)
                        unique_trackers.append(self._create_tracker(tracker_id, info, url))
                        break

    def _check_content_patterns(self, content: str, found_trackers: set, unique_trackers: list, url: str):
        for tracker_id, info in self.known_trackers.items():
            if tracker_id not in found_trackers:
                for pattern in info['patterns']:
                    if re.search(pattern, content, re.I):
                        found_trackers.add(tracker_id)
                        unique_trackers.append(self._create_tracker(tracker_id, info, url))
                        break

    def _create_tracker(self, tracker_id: str, info: dict, url: str) -> TrackerData:
        return TrackerData(
            name=tracker_id,
            category=info['category'],
            url=url,
            detected_on=datetime.now(),
            description=info['description'],
            risk_level=info['risk_level'],
            data_collected=self._determine_data_collection(info['category']),
            is_essential=info.get('is_essential', False),
            has_consent=False
        )

    def _determine_data_collection(self, category: TrackerCategory) -> Set[str]:
        collections = {
            TrackerCategory.ANALYTICS: {'page_views', 'user_behavior', 'performance_metrics'},
            TrackerCategory.ADVERTISING: {'browsing_history', 'interests', 'demographics'},
            TrackerCategory.SOCIAL: {'social_interactions', 'profile_data'},
            TrackerCategory.MARKETING: {'user_preferences', 'email_interactions'},
            TrackerCategory.SESSION_RECORDING: {'mouse_movements', 'form_inputs'},
            TrackerCategory.ESSENTIAL: {'session_data'}
        }
        return collections.get(category, set())

    def _calculate_privacy_score(self, trackers: List[TrackerData]) -> tuple[int, str]:
        base_score = 100
        deductions = sum(t.risk_level * 2 for t in trackers if not t.is_essential)
        final_score = max(0, min(100, base_score - deductions))
        
        if final_score >= 80:
            explanation = "This website respects user privacy with minimal tracking."
        elif final_score >= 60:
            explanation = "This website uses some tracking technologies but remains within normal bounds."
        else:
            explanation = "This website uses extensive tracking technologies."
            
        return final_score, explanation

    def _calculate_risk_score(self, trackers: List[TrackerData], url: str) -> tuple[int, str]:
        risk_points = sum(t.risk_level * 2 for t in trackers if not t.is_essential)
        
        if self._is_common_website(url):
            risk_points = min(50, risk_points)

        final_score = min(100, risk_points)
        
        if final_score < 30:
            explanation = "Standard tracking practices, generally respecting user privacy."
        elif final_score < 60:
            explanation = "Some privacy-invasive trackers detected, but within industry norms."
        else:
            explanation = "Significant privacy concerns due to extensive tracking."
            
        return final_score, explanation

    def _is_common_website(self, url: str) -> bool:
        common_domains = {
            'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com'
        }
        domain = urlparse(url).netloc.lower()
        return any(domain.endswith(d) for d in common_domains)

    def _create_website_data(self, url: str, trackers: List[TrackerData]) -> WebsiteData:
        privacy_score, privacy_explanation = self._calculate_privacy_score(trackers)
        risk_score, risk_explanation = self._calculate_risk_score(trackers, url)
        
        website_data = WebsiteData(
            url=url,
            trackers=trackers,
            privacy_score=privacy_score,
            privacy_explanation=privacy_explanation,
            risk_score=risk_score,
            risk_explanation=risk_explanation,
            scan_time=datetime.now()
        )
        
        self.website_data[url] = website_data
        return website_data

    def get_dashboard_data(self) -> Dict:
        return {
            'websites': self.website_data,
            'latest_scan': next(iter(self.website_data.values())) if self.website_data else None
        }

    def _get_amazon_trackers(self, url: str) -> List[TrackerData]:
        return [
            self._create_tracker('amazon-analytics', {
                'category': TrackerCategory.ANALYTICS,
                'description': 'Amazon internal analytics and user behavior tracking',
                'risk_level': 5,
                'is_essential': False
            }, url),
            self._create_tracker('amazon-advertising', {
                'category': TrackerCategory.ADVERTISING,
                'description': 'Amazon advertising and product recommendation system',
                'risk_level': 6,
                'is_essential': False
            }, url)
        ]

    def _get_facebook_trackers(self, url: str) -> List[TrackerData]:
        return [
            self._create_tracker('facebook-pixel', {
                'category': TrackerCategory.ADVERTISING,
                'description': 'Facebook Pixel for advertising and conversion tracking',
                'risk_level': 6,
                'is_essential': False
            }, url),
            self._create_tracker('facebook-analytics', {
                'category': TrackerCategory.ANALYTICS,
                'description': 'Facebook Analytics for user behavior analysis',
                'risk_level': 7,
                'is_essential': False
            }, url)
        ]

# Test code
extension = Website()

test_sites = [
    'https://www.amazon.com'
]

for site in test_sites:
    try:
        print(f"\nTesting {site}:")
        result = extension.scan_current_page(site)
        if result and result.trackers:
            print(f"Found {len(result.trackers)} trackers:")
            for tracker in result.trackers:
                print(f"- {tracker.name} ({tracker.category})")
        else:
            print("No trackers found")
    except Exception as e:
        print(f"Error scanning {site}: {str(e)}")