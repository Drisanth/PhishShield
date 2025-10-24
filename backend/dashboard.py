import json
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import pandas as pd
from flask import Flask, render_template_string, jsonify

class ScanDashboard:
    def __init__(self, scan_history_file="scan_history.json"):
        self.scan_history_file = scan_history_file
        self.scan_history = self.load_scan_history()
    
    def load_scan_history(self):
        """Load scan history from JSON file"""
        if not os.path.exists(self.scan_history_file):
            return []
        
        with open(self.scan_history_file, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    
    def save_scan_history(self):
        """Save scan history to JSON file"""
        with open(self.scan_history_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_history, f, indent=4, ensure_ascii=False)
    
    def add_scan_record(self, email_data, analysis_result):
        """Add a new scan record to history"""
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "email_data": {
                "sender": email_data.get('sender', ''),
                "subject": email_data.get('subject', ''),
                "body_length": len(email_data.get('body', '')),
                "links_count": len(email_data.get('links', []))
            },
            "analysis_result": {
                "header_score": analysis_result.get('header_score', 0),
                "body_score": analysis_result.get('body_score', 0),
                "bert_score": analysis_result.get('bert_score', 0),
                "feedback_score": analysis_result.get('feedback_score', 0),
                "link_score": analysis_result.get('link_score', 0),
                "final_score": analysis_result.get('final_score', 0),
                "verdict": analysis_result.get('verdict', '')
            }
        }
        
        self.scan_history.append(scan_record)
        self.save_scan_history()
    
    def get_dashboard_stats(self, days=7):
        """Get dashboard statistics for the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_scans = [
            scan for scan in self.scan_history
            if datetime.fromisoformat(scan['timestamp']) >= cutoff_date
        ]
        
        if not recent_scans:
            return {
                "total_scans": 0,
                "phishing_detected": 0,
                "suspicious_detected": 0,
                "safe_detected": 0,
                "average_scores": {},
                "top_senders": [],
                "scan_trends": [],
                "recent_scans": []
            }
        
        # Basic statistics
        total_scans = len(recent_scans)
        verdicts = [scan['analysis_result']['verdict'] for scan in recent_scans]
        verdict_counts = Counter(verdicts)
        
        phishing_detected = verdict_counts.get('Phishing 🚨', 0)
        suspicious_detected = verdict_counts.get('Suspicious ⚠️', 0)
        safe_detected = verdict_counts.get('Safe ✅', 0)
        
        # Average scores
        scores = ['header_score', 'body_score', 'bert_score', 'feedback_score', 'link_score', 'final_score']
        average_scores = {}
        for score in scores:
            values = [scan['analysis_result'][score] for scan in recent_scans if score in scan['analysis_result']]
            average_scores[score] = round(sum(values) / len(values), 3) if values else 0
        
        # Top senders
        senders = [scan['email_data']['sender'] for scan in recent_scans]
        top_senders = Counter(senders).most_common(5)
        
        # Scan trends (daily counts)
        daily_counts = defaultdict(int)
        for scan in recent_scans:
            date = datetime.fromisoformat(scan['timestamp']).date()
            daily_counts[date] += 1
        
        scan_trends = [
            {"date": str(date), "count": count}
            for date, count in sorted(daily_counts.items())
        ]
        
        # Recent scans (last 10)
        recent_scans_list = recent_scans[-10:]
        for scan in recent_scans_list:
            scan['timestamp'] = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M')
        
        return {
            "total_scans": total_scans,
            "phishing_detected": phishing_detected,
            "suspicious_detected": suspicious_detected,
            "safe_detected": safe_detected,
            "detection_rate": round((phishing_detected + suspicious_detected) / total_scans * 100, 1) if total_scans > 0 else 0,
            "average_scores": average_scores,
            "top_senders": [{"sender": sender, "count": count} for sender, count in top_senders],
            "scan_trends": scan_trends,
            "recent_scans": recent_scans_list
        }
    
    def get_detailed_analysis(self, scan_id=None):
        """Get detailed analysis for a specific scan or all scans"""
        if scan_id is not None:
            # Return specific scan
            for scan in self.scan_history:
                if scan.get('id') == scan_id:
                    return scan
            return None
        
        # Return all scans with detailed analysis
        return self.scan_history
    
    def export_data(self, format='json'):
        """Export scan data in specified format"""
        if format == 'json':
            return json.dumps(self.scan_history, indent=2)
        elif format == 'csv':
            df = pd.DataFrame(self.scan_history)
            return df.to_csv(index=False)
        else:
            return "Unsupported format"

# Global instance
scan_dashboard = ScanDashboard()
