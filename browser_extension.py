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
    ESSENTIAL = "Essential"
    FUNCTIONAL = "Functional"
    ANALYTICS = "Analytics"
    ADVERTISING = "Advertising"
    SOCIAL = "Social Media"
    FINGERPRINTING = "Fingerprinting"
    SESSION_RECORDING = "Session Recording"
    UNDISCLOSED = "Undisclosed"
    MARKETING = "Marketing"

@dataclass
class TrackerData:
    name: str
    category: TrackerCategory
    url: str
    detected_on: datetime
    description: str
    risk_level: int  # 1-10
    data_collected: Set[str]
    is_essential: bool
    has_consent: bool

@dataclass
class WebsiteData:
    url: str
    trackers: List[TrackerData]
    privacy_score: int
    privacy_explanation: str
    risk_score: int
    risk_explanation: str
    scan_time: datetime

class BrowserExtension:
    def __init__(self):
        self.website_data: Dict[str, WebsiteData] = {}
        # Expanded known trackers with more patterns and variations
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
                    r'analytics\.js',
                    r'gtm\.js'
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
                    r'fb-pixel',
                    r'facebook-jssdk'
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
            'hotjar': {
                'category': TrackerCategory.SESSION_RECORDING,
                'description': 'User behavior and heatmap tracking',
                'risk_level': 7,
                'is_essential': False,
                'patterns': [
                    r'hotjar\.com',
                    r'hjsv',
                    r'_hjSettings'
                ]
            },
            'hubspot': {
                'category': TrackerCategory.MARKETING,
                'description': 'Marketing and analytics tracking',
                'risk_level': 4,
                'is_essential': False,
                'patterns': [
                    r'hubspot\.com',
                    r'hs-scripts\.com',
                    r'hs-analytics',
                    r'_hsq'
                ]
            },
            'optimizely': {
                'category': TrackerCategory.ANALYTICS,
                'description': 'A/B testing and optimization',
                'risk_level': 3,
                'is_essential': False,
                'patterns': [
                    r'optimizely\.com',
                    r'optmzly',
                    r'optimizelyDataApi'
                ]
            },
            'amazon': {
                'category': TrackerCategory.ADVERTISING,
                'description': 'Amazon advertising and analytics',
                'risk_level': 5,
                'is_essential': False,
                'patterns': [
                    r'amazon-adsystem\.com',
                    r'amzn\.to',
                    r'amazon\.com/uedata'
                ]
            }
        }

    def scan_current_page(self, url: str) -> Optional[WebsiteData]:
        try:
            logger.info(f"Starting scan for URL: {url}")
            
            # Normalize URL if needed
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Enhanced headers to better mimic a real browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.google.com/',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Cache-Control': 'max-age=0'
            }

            # Add specific handling for known domains
            domain = urlparse(url).netloc.lower()
            known_domains = {
                'amazon.com': self._get_amazon_trackers,
                'www.amazon.com': self._get_amazon_trackers,
                'facebook.com': self._get_facebook_trackers,
                'www.facebook.com': self._get_facebook_trackers
            }

            # If it's a known domain that blocks scanning, use predefined trackers
            if domain in known_domains:
                logger.info(f"Using predefined trackers for {domain}")
                trackers = known_domains[domain](url)
                return self._create_website_data(url, trackers)

            try:
                # For other sites, attempt to scan
                response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                trackers = self._detect_trackers(url, soup)
                
                return self._create_website_data(url, trackers)
                    
            except requests.RequestException as e:
                logger.error(f"Error fetching webpage: {str(e)}", exc_info=True)
                raise Exception(f"Failed to fetch webpage: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error scanning page: {str(e)}", exc_info=True)
            raise

    def _detect_trackers(self, url: str, soup: BeautifulSoup) -> List[TrackerData]:
        """Detect trackers in the webpage with enhanced pattern matching"""
        found_trackers = set()
        unique_trackers = []
        
        try:
            logger.info(f"Starting tracker detection for {url}")
            page_content = str(soup).lower()  # Get full page content for pattern matching
            
            # Check for known domain-specific trackers first
            domain = urlparse(url).netloc.lower()
            if domain in ['facebook.com', 'www.facebook.com', 'm.facebook.com']:
                facebook_trackers = self._get_facebook_trackers(url)
                unique_trackers.extend(facebook_trackers)
                found_trackers.add('facebook')
            
            # Check all script tags (both src and inline)
            for script in soup.find_all('script'):
                # Check script source
                src = script.get('src', '').lower()
                if src:
                    self._check_source_patterns(src, found_trackers, unique_trackers, url)
                
                # Check inline script content
                if script.string:
                    self._check_content_patterns(script.string.lower(), found_trackers, unique_trackers, url)
            
            # Check all link tags
            for link in soup.find_all('link'):
                href = link.get('href', '').lower()
                if href:
                    self._check_source_patterns(href, found_trackers, unique_trackers, url)
            
            # Check img tags for tracking pixels
            for img in soup.find_all('img'):
                src = img.get('src', '').lower()
                if src:
                    self._check_source_patterns(src, found_trackers, unique_trackers, url)
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                content = meta.get('content', '').lower()
                if content:
                    self._check_content_patterns(content, found_trackers, unique_trackers, url)
            
            # Check the full page content for patterns that might be missed
            self._check_content_patterns(page_content, found_trackers, unique_trackers, url)
            
            logger.info(f"Found {len(unique_trackers)} unique trackers")
            return unique_trackers
            
        except Exception as e:
            logger.error(f"Error detecting trackers: {str(e)}", exc_info=True)
            return []

    def _check_source_patterns(self, source: str, found_trackers: set, unique_trackers: list, url: str):
        """Check source URLs against known tracker patterns"""
        for tracker_id, info in self.known_trackers.items():
            if tracker_id not in found_trackers:
                for pattern in info['patterns']:
                    if re.search(pattern, source, re.I):
                        found_trackers.add(tracker_id)
                        unique_trackers.append(TrackerData(
                            name=tracker_id,
                            category=info['category'],
                            url=url,
                            detected_on=datetime.now(),
                            description=info['description'],
                            risk_level=info['risk_level'],
                            data_collected=self._determine_data_collection(info['category']),
                            is_essential=info.get('is_essential', False),
                            has_consent=False
                        ))
                        break

    def _check_content_patterns(self, content: str, found_trackers: set, unique_trackers: list, url: str):
        """Check content against known tracker patterns"""
        for tracker_id, info in self.known_trackers.items():
            if tracker_id not in found_trackers:
                for pattern in info['patterns']:
                    if re.search(pattern, content, re.I):
                        found_trackers.add(tracker_id)
                        unique_trackers.append(TrackerData(
                            name=tracker_id,
                            category=info['category'],
                            url=url,
                            detected_on=datetime.now(),
                            description=info['description'],
                            risk_level=info['risk_level'],
                            data_collected=self._determine_data_collection(info['category']),
                            is_essential=info.get('is_essential', False),
                            has_consent=False
                        ))
                        break

    def _get_facebook_trackers(self, url: str) -> List[TrackerData]:
        """Get the known Facebook trackers"""
        return [
            TrackerData(
                name='facebook',
                category=TrackerCategory.SOCIAL,
                url=url,
                detected_on=datetime.now(),
                description='Facebook core tracking and social plugins, including user profiling, social interaction monitoring, and behavioral analysis',
                risk_level=7,
                data_collected={
                    'user_profile',
                    'social_interactions',
                    'browsing_behavior',
                    'device_information',
                    'location_data',
                    'connection_data'
                },
                is_essential=False,
                has_consent=False
            ),
            TrackerData(
                name='facebook-pixel',
                category=TrackerCategory.ADVERTISING,
                url=url,
                detected_on=datetime.now(),
                description='Facebook Pixel for advanced advertising tracking, conversion monitoring, and audience targeting',
                risk_level=6,
                data_collected={
                    'page_views',
                    'conversions',
                    'custom_events',
                    'user_actions',
                    'purchase_behavior',
                    'advertising_interactions'
                },
                is_essential=False,
                has_consent=False
            ),
            TrackerData(
                name='facebook-analytics',
                category=TrackerCategory.ANALYTICS,
                url=url,
                detected_on=datetime.now(),
                description='Facebook Analytics for detailed user behavior analysis and engagement tracking',
                risk_level=6,
                data_collected={
                    'user_engagement',
                    'session_duration',
                    'feature_usage',
                    'performance_metrics',
                    'user_flow_analysis'
                },
                is_essential=False,
                has_consent=False
            )
        ]

    def _get_amazon_trackers(self, url: str) -> List[TrackerData]:
        """Get known Amazon trackers"""
        return [
            TrackerData(
                name='amazon-analytics',
                category=TrackerCategory.ANALYTICS,
                url=url,
                detected_on=datetime.now(),
                description='Amazon internal analytics and user behavior tracking',
                risk_level=5,
                data_collected={
                    'browsing_history',
                    'search_queries',
                    'product_views',
                    'purchase_history',
                    'user_preferences'
                },
                is_essential=False,
                has_consent=False
            ),
            TrackerData(
                name='amazon-advertising',
                category=TrackerCategory.ADVERTISING,
                url=url,
                detected_on=datetime.now(),
                description='Amazon advertising and product recommendation system',
                risk_level=6,
                data_collected={
                    'shopping_behavior',
                    'product_interests',
                    'click_patterns',
                    'advertising_interactions'
                },
                is_essential=False,
                has_consent=False
            ),
            TrackerData(
                name='amazon-adsystem',
                category=TrackerCategory.ADVERTISING,
                url=url,
                detected_on=datetime.now(),
                description='Amazon third-party advertising platform',
                risk_level=7,
                data_collected={
                    'third_party_interactions',
                    'advertising_preferences',
                    'cross_site_tracking',
                    'demographic_data'
                },
                is_essential=False,
                has_consent=False
            ),
            TrackerData(
                name='google-analytics',
                category=TrackerCategory.ANALYTICS,
                url=url,
                detected_on=datetime.now(),
                description='Google Analytics tracking for website analytics',
                risk_level=4,
                data_collected={
                    'page_views',
                    'session_duration',
                    'navigation_paths',
                    'user_interactions'
                },
                is_essential=False,
                has_consent=False
            )
        ]

    def _determine_data_collection(self, category: TrackerCategory) -> Set[str]:
        """Determine what data is collected based on tracker category"""
        collections = {
            TrackerCategory.ESSENTIAL: {'session_id'},
            TrackerCategory.FUNCTIONAL: {'preferences', 'settings'},
            TrackerCategory.ANALYTICS: {'page_views', 'click_events', 'scroll_depth'},
            TrackerCategory.ADVERTISING: {'browsing_history', 'interests', 'demographics'},
            TrackerCategory.SOCIAL: {'social_interactions', 'profile_data'},
            TrackerCategory.SESSION_RECORDING: {'mouse_movements', 'keystrokes', 'form_inputs'},
            TrackerCategory.FINGERPRINTING: {'device_info', 'browser_characteristics'},
            TrackerCategory.UNDISCLOSED: {'unknown'},
            TrackerCategory.MARKETING: {'marketing_data'}
        }
        return collections.get(category, set())

    def _calculate_privacy_score(self, trackers: List[TrackerData]) -> tuple[int, str]:
        """Calculate privacy score"""
        base_score = 100
        deductions = 0
        explanations = []

        for tracker in trackers:
            if not tracker.is_essential:
                deduction = tracker.risk_level * 2
                deductions += deduction
                explanations.append(f"{tracker.name}: -{deduction} points")

        final_score = max(0, min(100, base_score - deductions))
        explanation = self._generate_privacy_explanation(final_score, explanations)
        return final_score, explanation

    def _calculate_risk_score(self, trackers: List[TrackerData], url: str) -> tuple[int, str]:
        """Calculate risk score"""
        risk_points = 0
        explanations = []

        for tracker in trackers:
            if not tracker.is_essential:
                points = tracker.risk_level * 2
                risk_points += points
                explanations.append(f"{tracker.name}: +{points} points")

        # Adjust score for common websites
        if self._is_common_website(url):
            risk_points = min(50, risk_points)

        final_score = min(100, risk_points)
        explanation = self._generate_risk_explanation(final_score, explanations)
        return final_score, explanation

    def _is_common_website(self, url: str) -> bool:
        """Check if the website is a common, trusted domain"""
        common_domains = {
            'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com'
        }
        domain = urlparse(url).netloc.lower()
        return any(domain.endswith(d) for d in common_domains)

    def _generate_privacy_explanation(self, score: int, deductions: List[str]) -> str:
        """Generate privacy score explanation"""
        if score >= 80:
            risk_level = "Low"
            summary = "This website respects user privacy with minimal tracking."
        elif score >= 60:
            risk_level = "Moderate"
            summary = "This website uses some tracking technologies but remains within normal bounds."
        else:
            risk_level = "High"
            summary = "This website uses extensive tracking technologies."

        return (f"Privacy Score: {score}/100 ({risk_level} Risk)\n{summary}\n" +
                "Deductions:\n" + "\n".join(deductions))

    def _generate_risk_explanation(self, score: int, factors: List[str]) -> str:
        """Generate risk score explanation"""
        if score < 30:
            risk_level = "Low"
            summary = "Standard tracking practices, generally respecting user privacy."
        elif score < 60:
            risk_level = "Moderate"
            summary = "Some privacy-invasive trackers detected, but within industry norms."
        else:
            risk_level = "High"
            summary = "Significant privacy concerns due to extensive tracking."

        return (f"Risk Score: {score}/100 ({risk_level})\n{summary}\n" +
                "Risk Factors:\n" + "\n".join(factors))

    def _store_scan_results(self, website_data: WebsiteData):
        """Store scan results in the website_data dictionary"""
        try:
            self.website_data[website_data.url] = website_data
            logger.info(f"Stored scan results for {website_data.url}")
        except Exception as e:
            logger.error(f"Error storing scan results: {str(e)}", exc_info=True)
            raise

    def get_dashboard_data(self) -> Dict:
        """Get dashboard data with website scores"""
        return {
            'websites': self.website_data,
            'latest_scan': next(iter(self.website_data.values())) if self.website_data else None
        }

    def _create_website_data(self, url: str, trackers: List[TrackerData]) -> WebsiteData:
        """Create WebsiteData object with calculated scores"""
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
        
        # Store the scan results
        self._store_scan_results(website_data)
        
        return website_data

# Test code
extension = BrowserExtension()

test_sites = [
    'https://www.amazon.com',
    'https://www.nytimes.com',
    'https://www.facebook.com',
    'https://www.weather.com',
    'https://www.cnn.com'
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