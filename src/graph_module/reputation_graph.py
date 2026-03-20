"""
Reputation Graph Module

Maintains a graph-based representation of sender-domain relationships
and tracks reputation drift over time to detect sudden changes.
"""

import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import json
import os


class ReputationGraph:
    """
    Graph-based reputation tracker for sender-domain relationships.
    
    This class maintains:
    - Sender-to-domain relationships
    - Historical reputation scores
    - Reputation drift detection
    - Temporal analysis of sender behavior
    """
    
    def __init__(self, persistence_file: Optional[str] = None):
        """
        Initialize the reputation graph.
        
        Args:
            persistence_file: Optional path to JSON file for persistence
        """
        self.graph = nx.DiGraph()  # Directed graph: sender -> domain
        self.sender_reputation = defaultdict(list)  # sender -> [(timestamp, score), ...]
        self.domain_reputation = defaultdict(list)  # domain -> [(timestamp, score), ...]
        self.persistence_file = persistence_file
        
        # Load existing data if file exists
        if persistence_file and os.path.exists(persistence_file):
            self.load_from_file(persistence_file)
    
    def add_interaction(self, sender: str, domain: str, timestamp: Optional[datetime] = None, 
                       phishing_score: float = 0.0):
        """
        Add a sender-domain interaction to the graph.
        
        Args:
            sender: Sender email address
            domain: Domain name
            timestamp: Timestamp of interaction (default: now)
            phishing_score: Phishing score for this interaction (0-1)
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Add edge to graph (or update if exists)
        if self.graph.has_edge(sender, domain):
            # Update edge data
            edge_data = self.graph[sender][domain]
            edge_data['count'] = edge_data.get('count', 0) + 1
            edge_data['last_seen'] = timestamp.isoformat()
            edge_data['scores'].append(phishing_score)
        else:
            # Create new edge
            self.graph.add_edge(sender, domain, 
                              count=1,
                              first_seen=timestamp.isoformat(),
                              last_seen=timestamp.isoformat(),
                              scores=[phishing_score])
        
        # Update sender reputation history
        self.sender_reputation[sender].append((timestamp, phishing_score))
        
        # Update domain reputation history
        self.domain_reputation[domain].append((timestamp, phishing_score))
        
        # Keep only last 1000 entries per sender/domain to prevent memory issues
        if len(self.sender_reputation[sender]) > 1000:
            self.sender_reputation[sender] = self.sender_reputation[sender][-1000:]
        if len(self.domain_reputation[domain]) > 1000:
            self.domain_reputation[domain] = self.domain_reputation[domain][-1000:]
    
    def get_sender_reputation(self, sender: str, lookback_days: int = 30) -> Dict[str, any]:
        """
        Get current reputation score for a sender.
        
        Args:
            sender: Sender email address
            lookback_days: Number of days to look back for reputation calculation
            
        Returns:
            Dictionary containing reputation metrics
        """
        if sender not in self.sender_reputation:
            return {
                'reputation_score': 0.5,  # Neutral if unknown
                'interaction_count': 0,
                'average_score': 0.5,
                'reputation_drift': 0.0,
                'is_known': False
            }
        
        cutoff_date = datetime.now() - timedelta(days=lookback_days)
        recent_interactions = [
            (ts, score) for ts, score in self.sender_reputation[sender]
            if ts >= cutoff_date
        ]
        
        if not recent_interactions:
            return {
                'reputation_score': 0.5,
                'interaction_count': 0,
                'average_score': 0.5,
                'reputation_drift': 0.0,
                'is_known': True
            }
        
        # Calculate average score (lower = more suspicious)
        scores = [score for _, score in recent_interactions]
        avg_score = sum(scores) / len(scores)
        
        # Calculate reputation drift (change over time)
        if len(recent_interactions) >= 2:
            # Compare first half vs second half
            mid = len(recent_interactions) // 2
            first_half_avg = sum(scores[:mid]) / mid
            second_half_avg = sum(scores[mid:]) / len(scores[mid:])
            drift = second_half_avg - first_half_avg  # Positive = getting worse
        else:
            drift = 0.0
        
        # Reputation score: 1.0 = good, 0.0 = bad
        # Invert phishing score (lower phishing score = higher reputation)
        reputation_score = 1.0 - avg_score
        
        return {
            'reputation_score': reputation_score,
            'interaction_count': len(recent_interactions),
            'average_score': avg_score,
            'reputation_drift': drift,
            'is_known': True
        }
    
    def get_domain_reputation(self, domain: str, lookback_days: int = 30) -> Dict[str, any]:
        """
        Get current reputation score for a domain.
        
        Args:
            domain: Domain name
            lookback_days: Number of days to look back for reputation calculation
            
        Returns:
            Dictionary containing reputation metrics
        """
        if domain not in self.domain_reputation:
            return {
                'reputation_score': 0.5,
                'interaction_count': 0,
                'average_score': 0.5,
                'reputation_drift': 0.0,
                'is_known': False
            }
        
        cutoff_date = datetime.now() - timedelta(days=lookback_days)
        recent_interactions = [
            (ts, score) for ts, score in self.domain_reputation[domain]
            if ts >= cutoff_date
        ]
        
        if not recent_interactions:
            return {
                'reputation_score': 0.5,
                'interaction_count': 0,
                'average_score': 0.5,
                'reputation_drift': 0.0,
                'is_known': True
            }
        
        scores = [score for _, score in recent_interactions]
        avg_score = sum(scores) / len(scores)
        
        # Calculate reputation drift
        if len(recent_interactions) >= 2:
            mid = len(recent_interactions) // 2
            first_half_avg = sum(scores[:mid]) / mid
            second_half_avg = sum(scores[mid:]) / len(scores[mid:])
            drift = second_half_avg - first_half_avg
        else:
            drift = 0.0
        
        reputation_score = 1.0 - avg_score
        
        return {
            'reputation_score': reputation_score,
            'interaction_count': len(recent_interactions),
            'average_score': avg_score,
            'reputation_drift': drift,
            'is_known': True
        }
    
    def detect_reputation_drift(self, sender: str, threshold: float = 0.3) -> bool:
        """
        Detect if sender has experienced significant reputation drift.
        
        Args:
            sender: Sender email address
            threshold: Threshold for drift detection (default: 0.3)
            
        Returns:
            True if significant drift detected
        """
        sender_rep = self.get_sender_reputation(sender)
        return abs(sender_rep['reputation_drift']) > threshold
    
    def get_related_domains(self, sender: str) -> List[str]:
        """
        Get all domains associated with a sender.
        
        Args:
            sender: Sender email address
            
        Returns:
            List of domain names
        """
        if sender in self.graph:
            return list(self.graph[sender].keys())
        return []
    
    def get_related_senders(self, domain: str) -> List[str]:
        """
        Get all senders associated with a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            List of sender email addresses
        """
        return [sender for sender, dom in self.graph.edges() if dom == domain]
    
    def analyze(self, email_data: Dict, phishing_score: float) -> Dict[str, any]:
        """
        Analyze email using graph-based reputation.
        
        Args:
            email_data: Dictionary containing processed email data
            phishing_score: Phishing score from other modules
            
        Returns:
            Dictionary containing graph analysis results
        """
        sender = email_data.get('headers', {}).get('from', '')
        domain = email_data.get('sender_domain')
        
        if not sender or not domain:
            return {
                'graph_score': 0.5,
                'sender_reputation': {},
                'domain_reputation': {},
                'reputation_drift': False,
                'explanation': 'Insufficient sender/domain information'
            }
        
        # Add interaction to graph
        self.add_interaction(sender, domain, phishing_score=phishing_score)
        
        # Get reputation scores
        sender_rep = self.get_sender_reputation(sender)
        domain_rep = self.get_domain_reputation(domain)
        
        # Detect drift
        drift_detected = self.detect_reputation_drift(sender)
        
        # Calculate graph-based score
        # Combine sender and domain reputation (weighted average)
        graph_score = (
            0.6 * sender_rep['reputation_score'] +
            0.4 * domain_rep['reputation_score']
        )
        
        # Adjust for drift
        if drift_detected and sender_rep['reputation_drift'] > 0:
            # Reputation getting worse
            graph_score *= 0.7
        
        # Generate explanation
        explanation_parts = []
        if sender_rep['is_known']:
            explanation_parts.append(f"Sender has {sender_rep['interaction_count']} recent interactions")
            if drift_detected:
                explanation_parts.append("Significant reputation drift detected")
        else:
            explanation_parts.append("Sender not seen before")
        
        if domain_rep['is_known']:
            explanation_parts.append(f"Domain has {domain_rep['interaction_count']} recent interactions")
        else:
            explanation_parts.append("Domain not seen before")
        
        explanation = "; ".join(explanation_parts)
        
        return {
            'graph_score': graph_score,
            'sender_reputation': sender_rep,
            'domain_reputation': domain_rep,
            'reputation_drift': drift_detected,
            'explanation': explanation
        }
    
    def save_to_file(self, filepath: Optional[str] = None):
        """
        Save graph data to JSON file.
        
        Args:
            filepath: Path to save file (uses self.persistence_file if None)
        """
        if filepath is None:
            filepath = self.persistence_file
        
        if filepath is None:
            return
        
        data = {
            'edges': [
                {
                    'sender': sender,
                    'domain': domain,
                    'data': self.graph[sender][domain]
                }
                for sender, domain in self.graph.edges()
            ],
            'sender_reputation': {
                sender: [(ts.isoformat(), score) for ts, score in history]
                for sender, history in self.sender_reputation.items()
            },
            'domain_reputation': {
                domain: [(ts.isoformat(), score) for ts, score in history]
                for domain, history in self.domain_reputation.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_from_file(self, filepath: str):
        """
        Load graph data from JSON file.
        
        Args:
            filepath: Path to load file from
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Rebuild graph
            for edge in data.get('edges', []):
                sender = edge['sender']
                domain = edge['domain']
                edge_data = edge['data']
                self.graph.add_edge(sender, domain, **edge_data)
            
            # Rebuild reputation histories
            for sender, history in data.get('sender_reputation', {}).items():
                self.sender_reputation[sender] = [
                    (datetime.fromisoformat(ts), score)
                    for ts, score in history
                ]
            
            for domain, history in data.get('domain_reputation', {}).items():
                self.domain_reputation[domain] = [
                    (datetime.fromisoformat(ts), score)
                    for ts, score in history
                ]
        except Exception as e:
            print(f"Error loading graph data: {e}")

