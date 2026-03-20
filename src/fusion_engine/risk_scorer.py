"""
Risk Scoring Engine

Combines scores from NLP, metadata, and graph modules to produce
a final phishing risk score with explanations.
"""

from typing import Dict, Optional, List

# Risk threshold constant for easy tuning
RISK_THRESHOLD = 0.6  # Base threshold for high-risk classification


class RiskScorer:
    """
    Hybrid risk scoring engine that combines multiple detection signals.
    
    This class:
    - Combines NLP, metadata, and graph scores
    - Applies weighted fusion
    - Generates comprehensive explanations
    - Provides confidence intervals
    """
    
    def __init__(self, 
                 nlp_weight: float = 0.45,
                 metadata_weight: float = 0.35,
                 graph_weight: float = 0.20):
        """
        Initialize the risk scorer.
        
        Args:
            nlp_weight: Weight for NLP analysis score (default: 0.45)
            metadata_weight: Weight for metadata analysis score (default: 0.35)
            graph_weight: Weight for graph analysis score (default: 0.20)
        """
        # Normalize weights
        total_weight = nlp_weight + metadata_weight + graph_weight
        self.nlp_weight = nlp_weight / total_weight
        self.metadata_weight = metadata_weight / total_weight
        self.graph_weight = graph_weight / total_weight
    
    def fuse_scores(self, 
                   nlp_score: float,
                   metadata_score: float,
                   graph_score: float) -> Dict[str, any]:
        """
        Fuse individual module scores into final risk score.
        
        Args:
            nlp_score: NLP phishing score (0-1, higher = more phishing)
            metadata_score: Metadata trust score (0-1, higher = more trustworthy)
            graph_score: Graph reputation score (0-1, higher = better reputation)
            
        Returns:
            Dictionary containing fused score and components
        """
        # Convert metadata and graph scores to phishing scores
        # (invert: higher trust = lower phishing probability)
        metadata_phishing = 1.0 - metadata_score
        graph_phishing = 1.0 - graph_score
        
        # Weighted fusion
        final_score = (
            self.nlp_weight * nlp_score +
            self.metadata_weight * metadata_phishing +
            self.graph_weight * graph_phishing
        )
        
        # Ensure score is in [0, 1] range
        final_score = max(0.0, min(1.0, final_score))
        
        return {
            'final_score': final_score,
            'nlp_contribution': self.nlp_weight * nlp_score,
            'metadata_contribution': self.metadata_weight * metadata_phishing,
            'graph_contribution': self.graph_weight * graph_phishing
        }
    
    def calculate_confidence(self, 
                            nlp_analysis: Dict,
                            metadata_analysis: Dict,
                            graph_analysis: Dict) -> float:
        """
        Calculate confidence in the final score.
        
        Args:
            nlp_analysis: NLP analysis results
            metadata_analysis: Metadata analysis results
            graph_analysis: Graph analysis results
            
        Returns:
            Confidence score (0-1)
        """
        confidence_factors = []
        
        # NLP confidence
        nlp_conf = nlp_analysis.get('transformer_analysis', {}).get('confidence', 0.5)
        confidence_factors.append(nlp_conf)
        
        # Metadata confidence (based on completeness)
        metadata_complete = (
            metadata_analysis.get('spf_check', {}).get('has_spf') is not None and
            metadata_analysis.get('dmarc_check', {}).get('has_dmarc') is not None
        )
        confidence_factors.append(1.0 if metadata_complete else 0.5)
        
        # Graph confidence (based on known sender/domain)
        sender_known = graph_analysis.get('sender_reputation', {}).get('is_known', False)
        domain_known = graph_analysis.get('domain_reputation', {}).get('is_known', False)
        graph_conf = 1.0 if (sender_known or domain_known) else 0.5
        confidence_factors.append(graph_conf)
        
        # Average confidence
        return sum(confidence_factors) / len(confidence_factors)
    
    def generate_explanation(self,
                            final_score: float,
                            nlp_analysis: Dict,
                            metadata_analysis: Dict,
                            graph_analysis: Dict,
                            boost_reasons: List[str] = None) -> str:
        """
        Generate human-readable explanation of the risk score.
        
        Args:
            final_score: Final phishing risk score (0-1)
            nlp_analysis: NLP analysis results
            metadata_analysis: Metadata analysis results
            graph_analysis: Graph analysis results
            boost_reasons: List of reasons for risk boost (optional)
            
        Returns:
            Explanation string
        """
        # Determine risk level with adjusted thresholds
        RISK_THRESHOLD_CRITICAL = 0.75
        RISK_THRESHOLD_HIGH = RISK_THRESHOLD  # Use constant (0.6)
        RISK_THRESHOLD_MEDIUM = 0.45
        RISK_THRESHOLD_LOW = 0.30
        
        if final_score >= RISK_THRESHOLD_CRITICAL:
            risk_level = "CRITICAL"
        elif final_score >= RISK_THRESHOLD_HIGH:
            risk_level = "HIGH"
        elif final_score >= RISK_THRESHOLD_MEDIUM:
            risk_level = "MEDIUM"
        elif final_score >= RISK_THRESHOLD_LOW:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        explanation_parts = [f"Overall Risk Level: {risk_level} ({final_score:.1%})"]
        
        # Add boost reasons if present
        if boost_reasons and len(boost_reasons) > 0:
            boost_text = ", ".join(boost_reasons)
            explanation_parts.append(f"Boost Reason: {boost_text}")
        
        # Add key indicators
        if nlp_analysis.get('phishing_score', 0) > 0.7:
            explanation_parts.append("⚠️ High phishing indicators in email content")
        
        if metadata_analysis.get('metadata_score', 1.0) < 0.3:
            explanation_parts.append("⚠️ Suspicious domain metadata detected")
        
        if graph_analysis.get('reputation_drift', False):
            explanation_parts.append("⚠️ Significant reputation drift detected")
        
        # Add specific details
        nlp_explanation = nlp_analysis.get('explanation', '')
        if nlp_explanation:
            explanation_parts.append(f"Content Analysis: {nlp_explanation}")
        
        metadata_explanation = metadata_analysis.get('explanation', '')
        if metadata_explanation:
            explanation_parts.append(f"Domain Analysis: {metadata_explanation}")
        
        graph_explanation = graph_analysis.get('explanation', '')
        if graph_explanation:
            explanation_parts.append(f"Reputation Analysis: {graph_explanation}")
        
        return "\n".join(explanation_parts)
    
    def calculate_risk_boosts(self,
                             nlp_analysis: Dict,
                             metadata_analysis: Dict) -> Dict[str, any]:
        """
        Calculate risk boosts based on critical phishing indicators.
        
        Args:
            nlp_analysis: NLP analysis results
            metadata_analysis: Metadata analysis results
            
        Returns:
            Dictionary containing boost amount and reasons
        """
        boost_amount = 0.0
        boost_reasons = []
        
        # Check for SPF/DMARC failures
        spf_check = metadata_analysis.get('spf_check', {})
        dmarc_check = metadata_analysis.get('dmarc_check', {})
        
        spf_failed = not spf_check.get('has_spf', False)
        dmarc_failed = not dmarc_check.get('has_dmarc', False)
        
        if spf_failed or dmarc_failed:
            boost_amount += 0.15  # +15% boost
            if spf_failed and dmarc_failed:
                boost_reasons.append("SPF and DMARC failed")
            elif spf_failed:
                boost_reasons.append("SPF failed")
            elif dmarc_failed:
                boost_reasons.append("DMARC failed")
        
        # Check for NLP phishing indicators
        phishing_keywords = nlp_analysis.get('phishing_keywords', [])
        urgency_score = nlp_analysis.get('urgency_score', 0.0)
        
        nlp_boost = 0.0
        if len(phishing_keywords) > 3:
            nlp_boost = 0.20  # +20% for >3 keywords
            boost_reasons.append(f"{len(phishing_keywords)} phishing keywords detected")
        elif len(phishing_keywords) >= 2:
            nlp_boost = 0.10  # +10% for 2-3 keywords
            boost_reasons.append(f"{len(phishing_keywords)} phishing keywords detected")
        
        if urgency_score > 0.5:
            urgency_boost = 0.15  # +15% for high urgency
            if nlp_boost < urgency_boost:
                nlp_boost = urgency_boost
            if "urgent tone detected" not in " ".join(boost_reasons):
                boost_reasons.append("urgent tone detected")
        
        boost_amount += nlp_boost
        
        # If both SPF/DMARC failure AND strong NLP indicators, ensure minimum 60% risk
        has_metadata_failure = spf_failed or dmarc_failed
        has_strong_nlp = len(phishing_keywords) > 3 or urgency_score > 0.5
        
        return {
            'boost_amount': min(boost_amount, 0.4),  # Cap boost at 40%
            'boost_reasons': boost_reasons,
            'has_metadata_failure': has_metadata_failure,
            'has_strong_nlp': has_strong_nlp,
            'requires_minimum_boost': has_metadata_failure and has_strong_nlp
        }
    
    def score(self,
             nlp_analysis: Dict,
             metadata_analysis: Dict,
             graph_analysis: Dict) -> Dict[str, any]:
        """
        Comprehensive risk scoring combining all analysis modules.
        
        Args:
            nlp_analysis: NLP analysis results
            metadata_analysis: Metadata analysis results
            graph_analysis: Graph analysis results
            
        Returns:
            Dictionary containing final risk assessment:
            {
                'final_score': float (0-1),
                'risk_level': str,
                'confidence': float (0-1),
                'explanation': str,
                'component_scores': dict,
                'recommendation': str,
                'boost_reasons': list,
                'boost_amount': float
            }
        """
        # Extract scores
        nlp_score = nlp_analysis.get('phishing_score', 0.5)
        metadata_score = metadata_analysis.get('metadata_score', 0.5)
        graph_score = graph_analysis.get('graph_score', 0.5)
        
        # Fuse scores with updated weights (NLP: 0.45, Metadata: 0.35, Graph: 0.20)
        fused = self.fuse_scores(nlp_score, metadata_score, graph_score)
        final_score = fused['final_score']
        
        # Calculate risk boosts based on critical indicators
        boost_info = self.calculate_risk_boosts(nlp_analysis, metadata_analysis)
        boost_amount = boost_info['boost_amount']
        boost_reasons = boost_info['boost_reasons']
        
        # Apply boost to final score
        if boost_amount > 0:
            final_score = final_score + boost_amount
        
        # If both metadata failure and strong NLP indicators, ensure minimum 60% risk
        if boost_info['requires_minimum_boost']:
            final_score = max(final_score, 0.6)
        
        # Apply conservative adjustments for trusted sources (reduce false positives)
        # Only reduce if there are NO strong phishing indicators
        if boost_amount == 0:
            metadata_trust = metadata_analysis.get('metadata_score', 0.5)
            if metadata_trust > 0.7:
                # High trust metadata - reduce phishing score by 15% (only for safe emails)
                final_score = final_score * 0.85
            
            # If graph shows known good sender/domain, reduce score further
            sender_known = graph_analysis.get('sender_reputation', {}).get('is_known', False)
            domain_known = graph_analysis.get('domain_reputation', {}).get('is_known', False)
            if sender_known or domain_known:
                graph_reputation = graph_analysis.get('graph_score', 0.5)
                if graph_reputation > 0.7:
                    # Known good reputation - reduce phishing score by 10% (only for safe emails)
                    final_score = final_score * 0.9
        
        # Ensure score stays in valid range [0, 1]
        final_score = max(0.0, min(1.0, final_score))
        
        # Calculate confidence
        confidence = self.calculate_confidence(nlp_analysis, metadata_analysis, graph_analysis)
        
        # Generate explanation with boost information
        explanation = self.generate_explanation(
            final_score, nlp_analysis, metadata_analysis, graph_analysis, boost_reasons
        )
        
        # Determine risk level with adjusted thresholds
        RISK_THRESHOLD_CRITICAL = 0.75
        RISK_THRESHOLD_HIGH = RISK_THRESHOLD  # Use constant (0.6)
        RISK_THRESHOLD_MEDIUM = 0.45
        RISK_THRESHOLD_LOW = 0.30  # Increased to ensure normal emails stay below
        
        if final_score >= RISK_THRESHOLD_CRITICAL:
            risk_level = "CRITICAL"
            recommendation = "BLOCK - This email is highly likely to be phishing"
        elif final_score >= RISK_THRESHOLD_HIGH:
            risk_level = "HIGH"
            recommendation = "QUARANTINE - Strong indicators of phishing"
        elif final_score >= RISK_THRESHOLD_MEDIUM:
            risk_level = "MEDIUM"
            recommendation = "REVIEW - Some suspicious indicators present"
        elif final_score >= RISK_THRESHOLD_LOW:
            risk_level = "LOW"
            recommendation = "MONITOR - Low risk but exercise caution"
        else:
            risk_level = "SAFE"
            recommendation = "ALLOW - Appears legitimate and safe"
        
        return {
            'final_score': final_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'explanation': explanation,
            'component_scores': {
                'nlp_score': nlp_score,
                'metadata_score': metadata_score,
                'graph_score': graph_score,
                'nlp_contribution': fused['nlp_contribution'],
                'metadata_contribution': fused['metadata_contribution'],
                'graph_contribution': fused['graph_contribution'],
                'boost_amount': boost_amount
            },
            'recommendation': recommendation,
            'boost_reasons': boost_reasons,
            'boost_amount': boost_amount
        }

