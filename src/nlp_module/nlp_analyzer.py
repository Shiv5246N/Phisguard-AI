"""
NLP Analyzer Module

Uses transformer-based models (DistilBERT/BERT) to detect phishing indicators
in email content through linguistic analysis.
"""

import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from typing import Dict, List, Optional
import numpy as np


class NLPAnalyzer:
    """
    NLP-based phishing detection using transformer models.
    
    This class analyzes email text for:
    - Social engineering patterns
    - Urgency indicators
    - Suspicious language patterns
    - Phishing probability scores
    """
    
    def __init__(self, model_name: str = "distilbert-base-uncased"):
        """
        Initialize the NLP analyzer.
        
        Args:
            model_name: HuggingFace model identifier
                       Default: "distilbert-base-uncased"
                       Alternative: "bert-base-uncased"
        """
        self.model_name = model_name
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize tokenizer and model
        # Note: For production, you would load a fine-tuned phishing detection model
        # Here we use a base model as a placeholder
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            # Using a generic text classification model as placeholder
            # In production, replace with a fine-tuned phishing detection model
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2  # Binary classification: phishing vs legitimate
            )
            self.model.eval()
            self.model.to(self.device)
        except Exception as e:
            print(f"Warning: Could not load model {model_name}. Using rule-based fallback.")
            self.model = None
            self.tokenizer = None
    
    def extract_phishing_keywords(self, text: str) -> List[str]:
        """
        Extract common phishing keywords and patterns.
        
        Args:
            text: Email text content
            
        Returns:
            List of detected phishing keywords
        """
        phishing_keywords = [
            'urgent', 'immediately', 'verify', 'account suspended', 'click here',
            'limited time', 'act now', 'confirm your identity', 'security alert',
            'unauthorized access', 'update payment', 'verify account', 'suspended',
            'expire', 'expiring', 'verify now', 'click below', 'secure your account',
            'verify your email', 'account locked', 'action required', 'verify identity'
        ]
        
        text_lower = text.lower()
        detected = [kw for kw in phishing_keywords if kw in text_lower]
        return detected
    
    def detect_urgency_patterns(self, text: str) -> float:
        """
        Detect urgency indicators in text.
        
        Args:
            text: Email text content
            
        Returns:
            Urgency score (0.0 to 1.0)
        """
        urgency_patterns = [
            r'\b(urgent|asap|immediately|right away|hurry|expires?|deadline)\b',
            r'\b(within\s+\d+\s+(hours?|days?|minutes?))\b',
            r'\b(limited\s+time|act\s+now|don\'?t\s+wait)\b'
        ]
        
        text_lower = text.lower()
        urgency_count = 0
        
        for pattern in urgency_patterns:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            urgency_count += matches
        
        # Normalize to 0-1 scale (max 10 occurrences = 1.0)
        urgency_score = min(urgency_count / 10.0, 1.0)
        return urgency_score
    
    def detect_suspicious_patterns(self, text: str) -> Dict[str, float]:
        """
        Detect various suspicious patterns in email text.
        
        Args:
            text: Email text content
            
        Returns:
            Dictionary of pattern scores
        """
        patterns = {
            'grammar_errors': 0.0,
            'excessive_caps': 0.0,
            'suspicious_greeting': 0.0,
            'link_disguise': 0.0,
            'generic_greeting': 0.0
        }
        
        text_lower = text.lower()
        
        # Check for excessive capitalization
        if len(text) > 0:
            caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
            patterns['excessive_caps'] = min(caps_ratio * 2, 1.0)  # Threshold: 50% caps
        
        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear sir/madam', 'hello']
        patterns['generic_greeting'] = 1.0 if any(gg in text_lower for gg in generic_greetings) else 0.0
        
        # Check for suspicious greetings
        suspicious_greetings = ['dear valued', 'dear account holder', 'attention']
        patterns['suspicious_greeting'] = 1.0 if any(sg in text_lower for sg in suspicious_greetings) else 0.0
        
        # Check for link disguise patterns (common in phishing)
        link_patterns = [
            r'click\s+(here|below|now)',
            r'visit\s+(here|below)',
            r'follow\s+(this|the)\s+link'
        ]
        link_matches = sum(len(re.findall(p, text_lower)) for p in link_patterns)
        patterns['link_disguise'] = min(link_matches / 3.0, 1.0)
        
        return patterns
    
    def analyze_with_transformer(self, text: str) -> Dict[str, float]:
        """
        Analyze text using transformer model.
        
        Args:
            text: Email text content
            
        Returns:
            Dictionary containing model predictions and confidence scores
        """
        if not self.model or not self.tokenizer:
            # Fallback to rule-based analysis
            return {
                'phishing_probability': 0.5,
                'confidence': 0.3,
                'method': 'rule_based_fallback'
            }
        
        try:
            # Tokenize and encode
            inputs = self.tokenizer(
                text,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt"
            ).to(self.device)
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)
            
            # Extract phishing probability (assuming class 1 is phishing)
            phishing_prob = probabilities[0][1].item()
            confidence = abs(probabilities[0][1] - probabilities[0][0]).item()
            
            return {
                'phishing_probability': phishing_prob,
                'confidence': confidence,
                'method': 'transformer_model'
            }
        except Exception as e:
            print(f"Error in transformer analysis: {e}")
            return {
                'phishing_probability': 0.5,
                'confidence': 0.0,
                'method': 'error_fallback'
            }
    
    def analyze(self, email_data: Dict) -> Dict[str, any]:
        """
        Comprehensive NLP analysis of email content.
        
        Args:
            email_data: Dictionary containing processed email data
                       (from EmailProcessor.process_email())
            
        Returns:
            Dictionary containing NLP analysis results:
            {
                'phishing_score': float (0-1),
                'urgency_score': float (0-1),
                'suspicious_patterns': dict,
                'phishing_keywords': list,
                'transformer_analysis': dict,
                'explanation': str
            }
        """
        # Combine subject and body for analysis
        text = f"{email_data.get('subject', '')} {email_data.get('body_clean', '')}"
        
        if not text.strip():
            return {
                'phishing_score': 0.0,
                'urgency_score': 0.0,
                'suspicious_patterns': {},
                'phishing_keywords': [],
                'transformer_analysis': {},
                'explanation': 'No text content found'
            }
        
        # Extract phishing keywords
        phishing_keywords = self.extract_phishing_keywords(text)
        
        # Detect urgency
        urgency_score = self.detect_urgency_patterns(text)
        
        # Detect suspicious patterns
        suspicious_patterns = self.detect_suspicious_patterns(text)
        
        # Transformer-based analysis
        transformer_analysis = self.analyze_with_transformer(text)
        
        # Combine scores (weighted average)
        # Transformer model gets highest weight (0.4)
        # Pattern detection gets 0.35
        # Urgency gets 0.25
        
        pattern_score = np.mean(list(suspicious_patterns.values()))
        
        # Base score from transformer (default to 0.2 for unknown, not 0.5)
        transformer_prob = transformer_analysis.get('phishing_probability', 0.2)
        
        # Only use transformer if it has reasonable confidence
        if transformer_analysis.get('confidence', 0) < 0.3:
            # Low confidence - default to safe
            transformer_prob = 0.2
        
        phishing_score = (
            0.4 * transformer_prob +
            0.35 * pattern_score +
            0.25 * urgency_score
        )
        
        # Apply conservative threshold: require multiple strong indicators
        # If no strong indicators, reduce score significantly
        strong_indicators = 0
        if urgency_score > 0.6:
            strong_indicators += 1
        if pattern_score > 0.6:
            strong_indicators += 1
        if len(phishing_keywords) >= 3:
            strong_indicators += 1
        if transformer_prob > 0.7:
            strong_indicators += 1
        
        # If fewer than 2 strong indicators, reduce score (reduce false positives)
        if strong_indicators < 2:
            phishing_score = phishing_score * 0.5  # Halve the score
        
        # Ensure minimum score for clearly safe emails
        if urgency_score < 0.2 and pattern_score < 0.2 and len(phishing_keywords) == 0:
            phishing_score = min(phishing_score, 0.15)  # Cap at 15% for clearly safe emails
        
        # Generate explanation
        explanation_parts = []
        if phishing_keywords:
            explanation_parts.append(f"Found {len(phishing_keywords)} phishing keywords")
        if urgency_score > 0.5:
            explanation_parts.append("High urgency indicators detected")
        if pattern_score > 0.5:
            explanation_parts.append("Suspicious language patterns found")
        if transformer_analysis.get('phishing_probability', 0.5) > 0.7:
            explanation_parts.append("AI model indicates high phishing likelihood")
        
        explanation = "; ".join(explanation_parts) if explanation_parts else "No significant phishing indicators"
        
        return {
            'phishing_score': float(phishing_score),
            'urgency_score': float(urgency_score),
            'suspicious_patterns': suspicious_patterns,
            'phishing_keywords': phishing_keywords,
            'transformer_analysis': transformer_analysis,
            'explanation': explanation
        }
