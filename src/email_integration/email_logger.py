"""
Email Logging Module for PhishGuard-AI++

Logs analyzed emails to CSV file for tracking and analysis.
"""

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Logs directory
LOGS_DIR = Path(__file__).parent.parent.parent / 'logs'
LOG_FILE = LOGS_DIR / 'email_logs.csv'

# CSV columns
CSV_COLUMNS = ['timestamp', 'sender', 'subject', 'risk_score', 'alert_sent']


def ensure_logs_directory():
    """Create logs directory if it doesn't exist."""
    LOGS_DIR.mkdir(exist_ok=True)


def log_email_analysis(sender: str, subject: str, risk_score: float, alert_sent: bool):
    """
    Log email analysis result to CSV file.
    
    Args:
        sender: Email sender address
        subject: Email subject
        risk_score: Calculated risk score (0-1)
        alert_sent: Whether alert was sent
    """
    try:
        ensure_logs_directory()
        
        # Check if file exists to determine if we need to write headers
        file_exists = LOG_FILE.exists()
        
        # Open file in append mode
        with open(LOG_FILE, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
            
            # Write header if file is new
            if not file_exists:
                writer.writeheader()
            
            # Write row
            writer.writerow({
                'timestamp': datetime.now().isoformat(),
                'sender': sender,
                'subject': subject,
                'risk_score': f"{risk_score:.4f}",
                'alert_sent': 'Yes' if alert_sent else 'No'
            })
            
    except Exception as e:
        # Log error but don't fail the main process
        print(f"Warning: Failed to log email analysis: {e}")


def get_log_stats() -> Optional[dict]:
    """
    Get statistics from email logs.
    
    Returns:
        Dictionary with log statistics or None if no logs exist
    """
    try:
        if not LOG_FILE.exists():
            return None
        
        total_emails = 0
        alerts_sent = 0
        high_risk_count = 0
        
        with open(LOG_FILE, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                total_emails += 1
                if row['alert_sent'] == 'Yes':
                    alerts_sent += 1
                risk = float(row['risk_score'])
                if risk >= 0.6:
                    high_risk_count += 1
        
        return {
            'total_emails': total_emails,
            'alerts_sent': alerts_sent,
            'high_risk_count': high_risk_count
        }
        
    except Exception as e:
        print(f"Warning: Failed to get log stats: {e}")
        return None

