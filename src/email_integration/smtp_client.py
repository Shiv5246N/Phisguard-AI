"""
Gmail SMTP/IMAP Client for PhishGuard-AI++

This module provides functions to:
- Fetch latest emails from Gmail inbox via IMAP
- Send alert emails via Gmail SMTP

Uses SSL encryption (port 993 for IMAP, port 465 for SMTP).
"""

import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.header import decode_header
from typing import Tuple, Optional, List
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Gmail IMAP and SMTP settings
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465


def get_email_credentials() -> Tuple[str, str, str]:
    """
    Retrieve email credentials from environment variables.
    
    Returns:
        Tuple of (smtp_email, smtp_password, alert_receiver)
        
    Raises:
        ValueError: If required environment variables are not set
    """
    smtp_email = os.getenv('SMTP_EMAIL')
    smtp_pass = os.getenv('SMTP_PASS')
    alert_receiver = os.getenv('ALERT_RECEIVER')
    
    if not smtp_email or not smtp_pass or not alert_receiver:
        raise ValueError(
            "Missing required environment variables. "
            "Please set SMTP_EMAIL, SMTP_PASS, and ALERT_RECEIVER in .env file"
        )
    
    return smtp_email, smtp_pass, alert_receiver


def decode_mime_words(s: str) -> str:
    """
    Decode MIME encoded words in email headers.
    
    Args:
        s: String that may contain MIME encoded words
        
    Returns:
        Decoded string
    """
    if not s:
        return ""
    
    try:
        decoded_parts = decode_header(s)
        decoded_string = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_string += part
        return decoded_string
    except Exception as e:
        logger.warning(f"Error decoding header: {e}")
        return str(s)


def fetch_latest_emails(count: int = 5) -> List[Tuple[str, str, str]]:
    """
    Connect to Gmail IMAP and fetch the latest count emails from inbox.
    
    Args:
        count: Number of latest emails to fetch (default: 5)
        
    Returns:
        List of tuples [(subject, sender, body), ...] for the latest emails
        
    Raises:
        Exception: If connection or email fetching fails
    """
    try:
        # Get credentials
        smtp_email, smtp_pass, _ = get_email_credentials()
        
        logger.info("🔌 Connecting to Gmail IMAP...")
        
        # Connect to Gmail IMAP server with SSL
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        
        # Login
        mail.login(smtp_email, smtp_pass)
        logger.info("✅ Connected to Gmail")
        
        # Select inbox
        mail.select('inbox')
        
        # Search for all emails
        status, messages = mail.search(None, 'ALL')
        
        if status != 'OK':
            raise Exception("Failed to search emails")
        
        # Get list of email IDs
        email_ids = messages[0].split()
        
        if not email_ids:
            logger.warning("⚠️ No new emails found in inbox")
            mail.logout()
            return []
        
        # Get the latest count emails (last count in the list)
        # Reverse to get most recent first
        email_ids_to_fetch = email_ids[-count:] if len(email_ids) >= count else email_ids
        email_ids_to_fetch.reverse()  # Most recent first
        
        emails = []
        total_emails = len(email_ids_to_fetch)
        
        # Fetch each email
        for idx, email_id in enumerate(email_ids_to_fetch, 1):
            try:
                # Fetch the email
                status, msg_data = mail.fetch(email_id, '(RFC822)')
                
                if status != 'OK':
                    logger.warning(f"Failed to fetch email {idx}/{total_emails}")
                    continue
                
                # Parse email
                raw_email = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                # Extract subject
                subject = decode_mime_words(email_message['Subject'] or '')
                
                # Extract sender
                sender = decode_mime_words(email_message['From'] or '')
                
                # Extract body (plain text only, ignore HTML and attachments)
                body = ""
                if email_message.is_multipart():
                    for part in email_message.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))
                        
                        # Skip attachments
                        if "attachment" in content_disposition:
                            continue
                        
                        # Extract plain text content only
                        if content_type == "text/plain":
                            try:
                                body_bytes = part.get_payload(decode=True)
                                if body_bytes:
                                    body = body_bytes.decode('utf-8', errors='ignore')
                                    break  # Prefer plain text
                            except Exception:
                                continue
                else:
                    # Single part message
                    content_type = email_message.get_content_type()
                    if content_type == "text/plain":
                        try:
                            body_bytes = email_message.get_payload(decode=True)
                            if body_bytes:
                                body = body_bytes.decode('utf-8', errors='ignore')
                        except Exception:
                            body = str(email_message.get_payload())
                
                # Add to list
                emails.append((subject, sender, body))
                
            except Exception as e:
                logger.warning(f"Error processing email {idx}/{total_emails}: {str(e)}")
                continue
        
        # Close connection
        mail.logout()
        
        return emails
        
    except imaplib.IMAP4.error as e:
        error_msg = f"IMAP error: {str(e)}"
        logger.error(f"❌ Error: Unable to connect to Gmail — check network or credentials.")
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Error fetching emails: {str(e)}"
        logger.error(f"❌ Error: {error_msg}")
        raise Exception(error_msg)


def fetch_latest_email() -> Tuple[str, str, str]:
    """
    Connect to Gmail IMAP and fetch the latest email from inbox.
    
    This is a convenience wrapper around fetch_latest_emails(count=1).
    
    Returns:
        Tuple of (subject, sender, body) for the latest email
        
    Raises:
        Exception: If connection or email fetching fails
    """
    emails = fetch_latest_emails(count=1)
    if emails:
        return emails[0]
    return "", "", ""


def send_alert(subject: str, message: str) -> bool:
    """
    Send alert email via Gmail SMTP.
    
    Args:
        subject: Email subject line
        message: Email message body
        
    Returns:
        True if email sent successfully, False otherwise
        
    Raises:
        Exception: If email sending fails
    """
    try:
        # Get credentials
        smtp_email, smtp_pass, alert_receiver = get_email_credentials()
        
        logger.info("🔌 Connecting to Gmail SMTP...")
        
        # Create message
        msg = MIMEText(message, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = smtp_email
        msg['To'] = alert_receiver
        
        # Connect to Gmail SMTP server with SSL
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        
        # Login
        server.login(smtp_email, smtp_pass)
        
        # Send email
        server.sendmail(smtp_email, alert_receiver, msg.as_string())
        
        # Close connection
        server.quit()
        
        logger.info(f"✅ Alert Sent to {alert_receiver}")
        return True
        
    except smtplib.SMTPException as e:
        error_msg = f"SMTP error: {str(e)}"
        logger.error(f"❌ Error: {error_msg}")
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Error sending alert: {str(e)}"
        logger.error(f"❌ Error: {error_msg}")
        raise Exception(error_msg)

