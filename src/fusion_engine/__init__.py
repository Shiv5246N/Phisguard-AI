"""
Fusion Engine Module for PhishGuard-AI++

This module combines scores from all detection modules into a final risk score.
"""

from .risk_scorer import RiskScorer

__all__ = ['RiskScorer']

