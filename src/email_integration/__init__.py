"""
Email Integration Module for PhishGuard-AI++

This module handles Gmail SMTP and IMAP integration for fetching emails
and sending phishing alerts.
"""

from .smtp_client import fetch_latest_email, fetch_latest_emails, send_alert
from .email_logger import log_email_analysis

__all__ = ['fetch_latest_email', 'fetch_latest_emails', 'send_alert', 'log_email_analysis']

