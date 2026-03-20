"""
Email Processor Module

Handles email ingestion, text cleaning, and feature extraction for phishing detection.
"""

import re
import email
from email.header import decode_header
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import html


class EmailProcessor:
    """
    Processes raw email content to extract clean text and metadata.
    
    This class handles:
    - Email parsing (from raw string or email.Message object)
    - Text cleaning and normalization
    - URL extraction
    - Header extraction (From, To, Subject, etc.)
    - HTML stripping
    """
    
    def __init__(self):
        """Initialize the email processor."""
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    
    def parse_email(self, email_content: str) -> email.message.Message:
        """
        Parse raw email string into email.Message object.
        
        Args:
            email_content: Raw email string
            
        Returns:
            Parsed email.Message object
        """
        try:
            return email.message_from_string(email_content)
        except Exception as e:
            # If parsing fails, create a simple message
            msg = email.message.Message()
            msg.set_payload(email_content)
            return msg
    
    def decode_header_value(self, header_value: Optional[str]) -> str:
        """
        Decode email header values that may be encoded.
        
        Args:
            header_value: Header value string (may be encoded)
            
        Returns:
            Decoded header string
        """
        if not header_value:
            return ""
        
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    decoded_string += part
            return decoded_string
        except Exception:
            return str(header_value)
    
    def extract_headers(self, msg: email.message.Message) -> Dict[str, str]:
        """
        Extract relevant email headers.
        
        Args:
            msg: Email message object
            
        Returns:
            Dictionary containing header fields
        """
        headers = {}
        
        # Extract common headers
        headers['from'] = self.decode_header_value(msg.get('From', ''))
        headers['to'] = self.decode_header_value(msg.get('To', ''))
        headers['subject'] = self.decode_header_value(msg.get('Subject', ''))
        headers['date'] = msg.get('Date', '')
        headers['reply_to'] = self.decode_header_value(msg.get('Reply-To', ''))
        headers['return_path'] = msg.get('Return-Path', '')
        
        # Extract authentication headers
        headers['spf'] = msg.get('Received-SPF', '')
        headers['dkim'] = msg.get('DKIM-Signature', '')
        headers['dmarc'] = msg.get('Authentication-Results', '')
        
        return headers
    
    def extract_body(self, msg: email.message.Message) -> Tuple[str, str]:
        """
        Extract plain text and HTML body from email.
        
        Args:
            msg: Email message object
            
        Returns:
            Tuple of (plain_text, html_text)
        """
        plain_text = ""
        html_text = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    body = part.get_payload(decode=True)
                    if body:
                        if content_type == "text/plain":
                            plain_text += body.decode('utf-8', errors='ignore')
                        elif content_type == "text/html":
                            html_text += body.decode('utf-8', errors='ignore')
                except Exception:
                    continue
        else:
            # Single part message
            try:
                body = msg.get_payload(decode=True)
                if body:
                    content_type = msg.get_content_type()
                    if content_type == "text/plain":
                        plain_text = body.decode('utf-8', errors='ignore')
                    elif content_type == "text/html":
                        html_text = body.decode('utf-8', errors='ignore')
            except Exception:
                plain_text = str(msg.get_payload())
        
        return plain_text, html_text
    
    def clean_text(self, text: str) -> str:
        """
        Clean and normalize text content.
        
        Args:
            text: Raw text string
            
        Returns:
            Cleaned text string
        """
        if not text:
            return ""
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s\.\,\!\?\:\;\-]', ' ', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text.
        
        Args:
            text: Text content to search
            
        Returns:
            List of extracted URLs
        """
        urls = self.url_pattern.findall(text)
        return list(set(urls))  # Remove duplicates
    
    def extract_emails(self, text: str) -> List[str]:
        """
        Extract all email addresses from text.
        
        Args:
            text: Text content to search
            
        Returns:
            List of extracted email addresses
        """
        emails = self.email_pattern.findall(text)
        return list(set(emails))  # Remove duplicates
    
    def extract_domain_from_email(self, email_address: str) -> Optional[str]:
        """
        Extract domain from email address.
        
        Args:
            email_address: Email address string
            
        Returns:
            Domain string or None
        """
        match = self.email_pattern.match(email_address)
        if match:
            return email_address.split('@')[-1].lower()
        return None
    
    def process_email(self, email_content: str) -> Dict:
        """
        Main method to process a complete email.
        
        Args:
            email_content: Raw email string or email.Message object
            
        Returns:
            Dictionary containing processed email data:
            {
                'headers': dict,
                'body_plain': str,
                'body_html': str,
                'body_clean': str,
                'urls': list,
                'emails': list,
                'sender_domain': str,
                'subject': str
            }
        """
        # Parse email if string provided
        if isinstance(email_content, str):
            msg = self.parse_email(email_content)
        else:
            msg = email_content
        
        # Extract components
        headers = self.extract_headers(msg)
        plain_text, html_text = self.extract_body(msg)
        
        # Combine text sources (prefer plain text)
        combined_text = plain_text if plain_text else html_text
        clean_text = self.clean_text(combined_text)
        
        # Extract URLs and emails
        urls = self.extract_urls(combined_text + html_text)
        emails = self.extract_emails(combined_text + headers.get('from', ''))
        
        # Extract sender domain
        sender_domain = None
        if headers.get('from'):
            sender_domain = self.extract_domain_from_email(headers['from'])
        
        return {
            'headers': headers,
            'body_plain': plain_text,
            'body_html': html_text,
            'body_clean': clean_text,
            'urls': urls,
            'emails': emails,
            'sender_domain': sender_domain,
            'subject': headers.get('subject', '')
        }

