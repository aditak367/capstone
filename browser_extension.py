from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import requests
from enum import Enum
from collections import Counter

class DataCategory(Enum):
    LOCATION = "Location Data"
    BROWSING = "Browsing History"
    PURCHASE = "Purchase Patterns"
    PERSONAL = "Personal Information"
    DEVICE = "Device Information"
    BEHAVIORAL = "Behavioral Data"

@dataclass
class ConsentRecord:
    website: str
    timestamp: datetime
    data_categories: List[DataCategory]
    purpose: str
    expiration: Optional[datetime]
    is_active: bool = True

@dataclass
class Tracker:
    name: str
    category: str
    risk_level: str
    data_collected: List[DataCategory]
    description: str
    recommendations: List[str]
    privacy_policy_url: Optional[str] = None
    company: Optional[str] = None

class PrivacyDashboard:
    def __init__(self):
        self.consent_history: List[ConsentRecord] = []
        self.site_ratings: Dict[str, float] = {}
        self.alternatives_database: Dict[str, List[str]] = self._load_alternatives()
        self.current_analysis = None

    def _load_alternatives(self) -> Dict[str, List[str]]:
        """
        Load privacy-friendly alternatives database from a JSON file
        """
        try:
            with open('privacy_alternatives.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "google.com": ["duckduckgo.com", "brave.com"],
                "facebook.com": ["mastodon.social", "diaspora*"],
                "youtube.com": ["peertube.social", "odysee.com"]
            }

    def _get_most_common_categories(self) -> List[DataCategory]:
        """
        Get the most common data categories from consent history
        """
        if not self.consent_history:
            return []
        
        category_counts = Counter()
        for consent in self.consent_history:
            category_counts.update(consent.data_categories)
        
        return [category for category, _ in category_counts.most_common(3)]

    def _analyze_consent_trend(self) -> Dict:
        """
        Analyze consent trends over time
        """
        if not self.consent_history:
            return {"trend": "No data available"}
        
        # Group consents by month
        monthly_consents = {}
        for consent in self.consent_history:
            month_key = consent.timestamp.strftime("%Y-%m")
            if month_key not in monthly_consents:
                monthly_consents[month_key] = 0
            monthly_consents[month_key] += 1
        
        return {
            "monthly_counts": monthly_consents,
            "total_months": len(monthly_consents),
            "average_consents_per_month": sum(monthly_consents.values()) / len(monthly_consents) if monthly_consents else 0
        }

    def _check_consent_expiration(self) -> float:
        """
        Check how many consents are close to expiration
        """
        if not self.consent_history:
            return 0.0
        
        current_time = datetime.now()
        expiring_soon = 0
        total_active = 0
        
        for consent in self.consent_history:
            if consent.is_active and consent.expiration:
                total_active += 1
                days_until_expiry = (consent.expiration - current_time).days
                if 0 < days_until_expiry <= 30:  # Consents expiring within 30 days
                    expiring_soon += 1
        
        return expiring_soon / total_active if total_active > 0 else 0.0

    def _generate_recommendations(self) -> List[str]:
        """
        Generate privacy recommendations based on current state
        """
        recommendations = []
        
        # Check for expiring consents
        expiring_ratio = self._check_consent_expiration()
        if expiring_ratio > 0.5:
            recommendations.append("Review and update expiring consents")
        
        # Check for high-risk trackers
        if self.current_analysis and self.current_analysis.get("trackers"):
            high_risk_trackers = [t for t in self.current_analysis["trackers"] 
                                if t.risk_level == "High"]
            if high_risk_trackers:
                recommendations.append("Consider blocking high-risk trackers")
        
        # Check for data collection patterns
        data_summary = self._summarize_data_collection()
        if data_summary["total_collections"] > 10:
            recommendations.append("Review data collection permissions")
        
        return recommendations

    def generate_privacy_report(self, timeframe: Optional[str] = "week") -> Dict:
        """
        Generate a comprehensive privacy report for the specified timeframe
        """
        return {
            "consent_summary": self._analyze_consent_history(),
            "risk_exposure": self._calculate_risk_exposure(),
            "recommendations": self._generate_recommendations(),
            "data_collection_summary": self._summarize_data_collection()
        }

    def _analyze_consent_history(self) -> Dict:
        """
        Analyze and summarize consent patterns
        """
        current_time = datetime.now()
        active_consents = [c for c in self.consent_history if c.is_active]
        expired_consents = [c for c in self.consent_history if not c.is_active]
        
        return {
            "total_consents": len(self.consent_history),
            "active_consents": len(active_consents),
            "expired_consents": len(expired_consents),
            "most_common_categories": self._get_most_common_categories(),
            "consent_trend": self._analyze_consent_trend()
        }

    def _calculate_risk_exposure(self) -> Dict:
        """
        Calculate overall privacy risk score
        """
        risk_score = 0.0
        risk_factors = {
            "active_trackers": len(self.current_analysis.get("trackers", [])),
            "data_categories": len(set().union(*[c.data_categories for c in self.consent_history])),
            "consent_expiration": self._check_consent_expiration()
        }
        
        risk_score = min(10.0, risk_factors["active_trackers"] * 0.5 + 
                        risk_factors["data_categories"] * 0.3 +
                        risk_factors["consent_expiration"] * 0.2)
        
        return {
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "risk_level": "High" if risk_score > 7 else "Medium" if risk_score > 4 else "Low"
        }

    def _summarize_data_collection(self) -> Dict:
        """
        Summarize types of data being collected
        """
        data_summary = {category: 0 for category in DataCategory}
        
        for consent in self.consent_history:
            for category in consent.data_categories:
                data_summary[category] += 1
        
        return {
            "data_categories": data_summary,
            "total_collections": sum(data_summary.values()),
            "most_collected": max(data_summary.items(), key=lambda x: x[1])[0] if data_summary else None
        }

class PrivacyAnalyzer:
    def __init__(self):
        self.dashboard = PrivacyDashboard()
        self.educational_content = self._load_educational_content()

    def _load_educational_content(self) -> Dict:
        """
        Load educational content about different tracking technologies
        """
        try:
            with open('educational_content.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "analytics": {
                    "title": "Understanding Analytics",
                    "content": "Analytics tools track website usage and user behavior...",
                    "tips": ["Use privacy-focused analytics", "Block third-party cookies"]
                },
                "advertising": {
                    "title": "Online Advertising",
                    "content": "Advertising trackers monitor your behavior for targeted ads...",
                    "tips": ["Use an ad blocker", "Enable tracking protection"]
                }
            }

    def analyze_website(self, url: str) -> Dict:
        """
        Comprehensive website analysis
        """
        trackers = self._detect_trackers(url)
        data_collection = self._analyze_data_collection(url)
        privacy_score = self._calculate_privacy_score(url)
        alternatives = self.dashboard.alternatives_database.get(url, [])

        analysis = {
            "url": url,
            "trackers": trackers,
            "data_collection": data_collection,
            "privacy_score": privacy_score,
            "alternatives": alternatives,
            "educational_tips": self._get_relevant_education(trackers)
        }
        
        self.dashboard.current_analysis = analysis
        return analysis

    def _detect_trackers(self, url: str) -> List[Tracker]:
        """
        Implement advanced tracker detection
        """
        return [
            Tracker(
                name="Google Analytics",
                category="Analytics",
                risk_level="Medium",
                data_collected=[DataCategory.BROWSING, DataCategory.BEHAVIORAL],
                description="Tracks website usage and user behavior",
                recommendations=["Use privacy-focused analytics", "Block third-party cookies"],
                privacy_policy_url="https://policies.google.com/privacy"
            ),
            Tracker(
                name="Facebook Pixel",
                category="Advertising",
                risk_level="High",
                data_collected=[DataCategory.BROWSING, DataCategory.PERSONAL],
                description="Tracks user behavior for targeted advertising",
                recommendations=["Use Facebook Container", "Block social media trackers"],
                privacy_policy_url="https://www.facebook.com/privacy/explanation"
            )
        ]

    def _analyze_data_collection(self, url: str) -> Dict[DataCategory, List[str]]:
        """
        Analyze what types of data are being collected
        """
        collection_map = {}
        trackers = self._detect_trackers(url)
        
        for tracker in trackers:
            for category in tracker.data_collected:
                if category not in collection_map:
                    collection_map[category] = []
                collection_map[category].append(tracker.name)
        
        return collection_map

    def _calculate_privacy_score(self, url: str) -> float:
        """
        Calculate a privacy score (0-10) based on various factors
        """
        score = 10.0
        trackers = self._detect_trackers(url)
        
        # Deduct points based on number of trackers
        score -= len(trackers) * 0.5
        
        # Deduct points based on risk levels
        for tracker in trackers:
            if tracker.risk_level == "High":
                score -= 1.0
            elif tracker.risk_level == "Medium":
                score -= 0.5
        
        # Deduct points based on data categories
        unique_categories = set()
        for tracker in trackers:
            unique_categories.update(tracker.data_collected)
        score -= len(unique_categories) * 0.3
        
        return max(0.0, min(10.0, score))

    def _get_relevant_education(self, trackers: List[Tracker]) -> List[Dict]:
        """
        Return relevant educational content based on detected trackers
        """
        education_list = []
        for tracker in trackers:
            if tracker.category.lower() in self.educational_content:
                education_list.append({
                    "tracker": tracker.name,
                    "content": self.educational_content[tracker.category.lower()]
                })
        return education_list

class BrowserExtension:
    def __init__(self):
        self.analyzer = PrivacyAnalyzer()
        self.dashboard = self.analyzer.dashboard
        self.current_analysis = None

    def scan_current_page(self, url: str) -> Dict:
        """
        Perform comprehensive page analysis and update dashboard
        """
        self.current_analysis = self.analyzer.analyze_website(url)
        return self.current_analysis

    def record_consent(self, website: str, data_categories: List[DataCategory], 
                      purpose: str, expiration: Optional[datetime] = None):
        """
        Record user consent for data collection
        """
        consent = ConsentRecord(
            website=website,
            timestamp=datetime.now(),
            data_categories=data_categories,
            purpose=purpose,
            expiration=expiration
        )
        self.dashboard.consent_history.append(consent)

    def get_dashboard_data(self) -> Dict:
        """
        Get current dashboard state for UI rendering
        """
        return {
            "current_analysis": self.current_analysis,
            "privacy_report": self.dashboard.generate_privacy_report(),
            "consent_history": self.dashboard.consent_history,
            "educational_content": self.analyzer.educational_content
        }

if __name__ == "__main__":
    extension = BrowserExtension()
    
    # Test scanning a website
    test_url = "https://www.lingscars.com/"
    analysis = extension.scan_current_page(test_url)
    print("Website Analysis:", analysis)
    
    # Test recording consent
    extension.record_consent(
        website=test_url,
        data_categories=[DataCategory.BROWSING, DataCategory.BEHAVIORAL],
        purpose="Analytics",
        expiration=datetime.now() + timedelta(days=30)
    )
    
    # Get dashboard data
    dashboard_data = extension.get_dashboard_data()
    print("\nDashboard Data:", dashboard_data)