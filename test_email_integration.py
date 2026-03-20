"""
Test Script for Email Integration with PhishGuard-AI

This script:
1. Fetches the 5 latest emails from Gmail inbox
2. Analyzes each using PhishGuard AI++ model
3. Sends alert if phishing risk > 60%
4. Logs all results to CSV

Usage:
    python test_email_integration.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.email_integration import fetch_latest_emails, send_alert, log_email_analysis
from src.preprocessing import EmailProcessor
from src.nlp_module import NLPAnalyzer
from src.metadata_module import MetadataAnalyzer
from src.graph_module import ReputationGraph
from src.fusion_engine import RiskScorer


def calculate_risk(email_text: str) -> dict:
    """
    Calculate phishing risk for an email using PhishGuard AI++.
    
    Args:
        email_text: Raw email text content
        
    Returns:
        Dictionary containing risk assessment results
    """
    # Initialize components
    email_processor = EmailProcessor()
    nlp_analyzer = NLPAnalyzer()
    metadata_analyzer = MetadataAnalyzer()
    reputation_graph = ReputationGraph(
        persistence_file='data/reputation_graph.json'
    )
    risk_scorer = RiskScorer()
    
    # Process email
    processed = email_processor.process_email(email_text)
    
    # Run analyses
    nlp_result = nlp_analyzer.analyze(processed)
    metadata_result = metadata_analyzer.analyze(processed)
    
    # Get initial phishing score for graph
    initial_phishing_score = nlp_result.get('phishing_score', 0.5)
    graph_result = reputation_graph.analyze(processed, initial_phishing_score)
    
    # Calculate final risk score
    risk_assessment = risk_scorer.score(
        nlp_result, metadata_result, graph_result
    )
    
    return risk_assessment


def main():
    """Main test function."""
    print("=" * 60)
    print("PhishGuard AI++ - Email Integration Test")
    print("=" * 60)
    print()
    
    try:
        # Step 1: Fetch latest 5 emails
        emails = fetch_latest_emails(count=5)
        
        if not emails:
            print("⚠️ No new emails found in inbox.")
            return
        
        # Step 2: Analyze each email
        results = []
        
        for idx, (subject, sender, body) in enumerate(emails, 1):
            try:
                # Prepare email text for analysis
                email_text = f"From: {sender}\n"
                email_text += f"To: user@company.com\n"
                email_text += f"Subject: {subject}\n\n"
                email_text += body
                
                # Analyze email
                risk_assessment = calculate_risk(email_text)
                final_score = risk_assessment['final_score']
                risk_level = risk_assessment['risk_level']
                
                # Determine risk status
                if final_score >= 0.75:
                    risk_status = "CRITICAL"
                elif final_score >= 0.6:
                    risk_status = "Phishing"
                else:
                    risk_status = "Safe"
                
                # Print formatted output as requested (matches example format)
                print(f"📩 [{idx}/{len(emails)}] From: {sender} — Subject: {subject}")
                print(f"Risk Score: {final_score*100:.1f}% ({risk_status})")
                
                # Check if alert should be sent
                alert_sent = False
                if final_score > 0.6:
                    # Prepare alert message
                    alert_subject = f"PhishGuard Alert: {subject}"
                    alert_message = (
                        f"Suspicious email detected from {sender}\n"
                        f"Risk Score: {final_score*100:.1f}%\n"
                        f"Risk Level: {risk_level}\n\n"
                        f"Subject: {subject}\n\n"
                        f"First 500 characters:\n{body[:500]}"
                    )
                    
                    # Send alert
                    try:
                        send_alert(alert_subject, alert_message)
                        alert_sent = True
                        print(f"✅ Alert sent to sunilprajapat11871@gmail.com")
                    except Exception as alert_error:
                        print(f"⚠️ Failed to send alert: {str(alert_error)}")
                
                # Log the analysis
                log_email_analysis(sender, subject, final_score, alert_sent)
                
                # Store result
                results.append({
                    'sender': sender,
                    'subject': subject,
                    'risk_score': final_score,
                    'risk_level': risk_level,
                    'risk_status': risk_status,
                    'alert_sent': alert_sent
                })
                
            except Exception as e:
                print(f"❌ Error analyzing email: {str(e)}")
                # Still log the email even if analysis failed
                log_email_analysis(sender, subject, 0.0, False)
                results.append({
                    'sender': sender,
                    'subject': subject,
                    'risk_score': 0.0,
                    'risk_level': 'ERROR',
                    'risk_status': 'ERROR',
                    'alert_sent': False
                })
            
            print()  # Blank line between emails
        
        # Step 3: Display summary
        print("=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"Total emails analyzed: {len(results)}")
        print(f"High-risk emails (risk > 60%): {sum(1 for r in results if r['risk_score'] > 0.6)}")
        print(f"Alerts sent: {sum(1 for r in results if r['alert_sent'])}")
        print()
        print("Detailed Results:")
        print("-" * 60)
        
        for idx, result in enumerate(results, 1):
            sender = result['sender']
            subject = result['subject']
            risk_score = result['risk_score']
            risk_status = result['risk_status']
            alert_sent = result['alert_sent']
            
            if risk_score > 0.6:
                print(f"[Email {idx}] From: {sender} — Subject: {subject}")
                print(f"  Risk: {risk_score*100:.1f}% ({risk_status}) — Alert Sent to sunilprajapat11871@gmail.com")
            else:
                print(f"[Email {idx}] From: {sender} — Subject: {subject}")
                print(f"  Risk: {risk_score*100:.1f}% ({risk_status}) — No Alert (Below Threshold)")
        
        print()
        print("✅ All analyses logged to logs/email_logs.csv")
        print()
        print("=" * 60)
        print("Test completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print()
        print("=" * 60)
        print("❌ Error occurred during test:")
        print("=" * 60)
        error_msg = str(e)
        if "Unable to connect" in error_msg or "IMAP" in error_msg:
            print("❌ Error: Unable to connect to Gmail — check network or credentials.")
        else:
            print(f"Error: {error_msg}")
        print()
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

