"""
PhishGuard-AI++ Demo Application
Streamlit UI for phishing detection demonstration
"""

import streamlit as st
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.preprocessing import EmailProcessor
from src.nlp_module import NLPAnalyzer
from src.metadata_module import MetadataAnalyzer
from src.graph_module import ReputationGraph
from src.fusion_engine import RiskScorer


# Page configuration
st.set_page_config(
    page_title="PhishGuard-AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'reputation_graph' not in st.session_state:
    st.session_state.reputation_graph = ReputationGraph(
        persistence_file='data/reputation_graph.json'
    )

# Initialize analyzers (cached for performance)
@st.cache_resource
def get_analyzers():
    """Initialize and cache analyzer instances."""
    return {
        'email_processor': EmailProcessor(),
        'nlp_analyzer': NLPAnalyzer(),
        'metadata_analyzer': MetadataAnalyzer(),
        'risk_scorer': RiskScorer()
    }


def main():
    """Main application function."""
    st.title("🛡️ PhishGuard AI")
    st.markdown("### Adaptive Hybrid System for Zero-Day Email Phishing Detection and Risk Intelligence")
    st.markdown("""
    PhishGuard-AI uses advanced machine learning and NLP to detect zero-day phishing emails
    by analyzing email content, sender metadata (SPF/DKIM/DMARC), and domain behavior patterns.
    """)
    
    # Get analyzers
    analyzers = get_analyzers()
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        st.markdown("---")
        
        st.subheader("Detection Weights")
        nlp_weight = st.slider("NLP Weight", 0.0, 1.0, 0.45, 0.05)
        metadata_weight = st.slider("Metadata Weight", 0.0, 1.0, 0.35, 0.05)
        graph_weight = st.slider("Graph Weight", 0.0, 1.0, 0.20, 0.05)
        
        # Normalize weights
        total = nlp_weight + metadata_weight + graph_weight
        if total > 0:
            nlp_weight /= total
            metadata_weight /= total
            graph_weight /= total
        
        analyzers['risk_scorer'].nlp_weight = nlp_weight
        analyzers['risk_scorer'].metadata_weight = metadata_weight
        analyzers['risk_scorer'].graph_weight = graph_weight
        
        st.markdown("---")
        st.markdown("### 📊 Statistics")
        graph = st.session_state.reputation_graph
        st.metric("Tracked Senders", len(graph.sender_reputation))
        st.metric("Tracked Domains", len(graph.domain_reputation))
        st.metric("Graph Edges", graph.graph.number_of_edges())
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["📧 Email Analysis", "🔗 URL Analysis", "ℹ️ About"])
    
    with tab1:
        st.header("Email Phishing Detection")
        st.markdown("Paste an email below to analyze it for phishing indicators.")
        
        # Input method selection
        input_method = st.radio(
            "Input Method",
            ["Raw Email Text", "Email Headers + Body"],
            horizontal=True
        )
        
        if input_method == "Raw Email Text":
            email_text = st.text_area(
                "Email Content",
                height=300,
                placeholder="""From: suspicious@example.com
To: user@company.com
Subject: Urgent: Verify Your Account

Dear Customer,

Your account will be suspended if you don't verify your identity immediately.
Click here to verify: http://verify-account.example.com

Thank you,
Security Team"""
            )
        else:
            col1, col2 = st.columns(2)
            with col1:
                email_headers = st.text_area(
                    "Email Headers",
                    height=200,
                    placeholder="""From: sender@domain.com
To: recipient@company.com
Subject: Important Notice
Date: Mon, 1 Jan 2024 12:00:00 +0000"""
                )
            with col2:
                email_body = st.text_area(
                    "Email Body",
                    height=200,
                    placeholder="Email body text here..."
                )
            email_text = f"{email_headers}\n\n{email_body}"
        
        if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
            if not email_text.strip():
                st.warning("Please enter email content to analyze.")
            else:
                with st.spinner("Analyzing email..."):
                    try:
                        # Process email
                        processed = analyzers['email_processor'].process_email(email_text)
                        
                        # Run analyses
                        nlp_result = analyzers['nlp_analyzer'].analyze(processed)
                        metadata_result = analyzers['metadata_analyzer'].analyze(processed)
                        
                        # Get initial phishing score for graph
                        initial_phishing_score = nlp_result.get('phishing_score', 0.5)
                        graph_result = st.session_state.reputation_graph.analyze(
                            processed, initial_phishing_score
                        )
                        
                        # Calculate final risk score
                        risk_assessment = analyzers['risk_scorer'].score(
                            nlp_result, metadata_result, graph_result
                        )
                        
                        # Display results
                        display_results(processed, nlp_result, metadata_result, 
                                      graph_result, risk_assessment)
                        
                    except Exception as e:
                        st.error(f"Error during analysis: {str(e)}")
                        st.exception(e)
    
    with tab2:
        st.header("URL Phishing Detection")
        st.markdown("Enter a URL to analyze its domain for phishing indicators.")
        
        url_input = st.text_input(
            "URL",
            placeholder="https://example.com/verify-account"
        )
        
        if st.button("🔍 Analyze URL", type="primary", use_container_width=True):
            if not url_input.strip():
                st.warning("Please enter a URL to analyze.")
            else:
                with st.spinner("Analyzing URL..."):
                    try:
                        # Extract domain
                        from urllib.parse import urlparse
                        parsed = urlparse(url_input)
                        domain = parsed.netloc or parsed.path.split('/')[0]
                        
                        if not domain:
                            st.error("Could not extract domain from URL.")
                        else:
                            # Create mock email data for analysis
                            mock_email_data = {
                                'sender_domain': domain,
                                'urls': [url_input],
                                'headers': {'from': f'noreply@{domain}'},
                                'body_clean': '',
                                'subject': ''
                            }
                            
                            # Run metadata analysis
                            metadata_result = analyzers['metadata_analyzer'].analyze(mock_email_data)
                            
                            # Display URL analysis results
                            display_url_results(domain, metadata_result)
                            
                    except Exception as e:
                        st.error(f"Error during URL analysis: {str(e)}")
                        st.exception(e)
    
    with tab3:
        st.header("About PhishGuard AI")
        st.markdown("""
        ### System Architecture
        
        PhishGuard AI combines multiple detection methodologies:
        
        1. **NLP Analysis Module**
           - Uses transformer-based models (DistilBERT/BERT) to detect linguistic manipulation
           - Identifies social engineering patterns and urgency indicators
           - Analyzes suspicious language patterns
        
        2. **Metadata Analysis Module**
           - Validates SPF/DKIM/DMARC records
           - Checks domain age using WHOIS lookups
           - Calculates domain entropy (random-looking domains are suspicious)
           - Detects suspicious TLDs
        
        3. **Graph-based Reputation Tracker**
           - Maintains sender-domain relationships
           - Tracks reputation over time
           - Detects sudden reputation drift
        
        4. **Hybrid Risk Scoring Engine**
           - Combines all signals using weighted fusion
           - Provides confidence intervals
           - Generates human-readable explanations
        
        ### How It Works
        
        When an email is analyzed:
        1. Email content is preprocessed and cleaned
        2. NLP module analyzes text for phishing indicators
        3. Metadata module checks domain authentication and age
        4. Graph module checks historical reputation
        5. Risk scorer combines all signals into final score
        
        ### Risk Levels
        
        - **CRITICAL** (≥75%): Highly likely phishing - BLOCK
        - **HIGH** (60-74%): Strong indicators - QUARANTINE
        - **MEDIUM** (45-59%): Some suspicious indicators - REVIEW
        - **LOW** (25-44%): Low risk - MONITOR
        - **SAFE** (<25%): Appears legitimate - ALLOW
        
        ### Developer Information
        
        **Name:** Sunil Prajapat  
        **Email:** [sunilprajapat2907@gmail.com](mailto:sunilprajapat2907@gmail.com)  
        
        Developed by Sunil Prajapat as part of a patent-ready AI cybersecurity project, **PhishGuard AI: Adaptive Hybrid System for Zero-Day Email Phishing Detection and Risk Intelligence**.
        """)
        
        # Single footer
        st.markdown("---")
        st.markdown(
            """
            <div style='text-align: center; color: #666; padding: 20px;'>
                <p>© 2026 PhishGuard AI | All Rights Reserved | Contact: sunilprajapat2907@gmail.com</p>
            </div>
            """,
            unsafe_allow_html=True
        )


def display_results(processed, nlp_result, metadata_result, graph_result, risk_assessment):
    """Display comprehensive analysis results."""
    
    # Final risk score (prominent)
    st.markdown("---")
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        final_score = risk_assessment['final_score']
        risk_level = risk_assessment['risk_level']
        
        # Color based on risk level (updated thresholds)
        if final_score >= 0.75:
            color = "🔴"
        elif final_score >= 0.60:
            color = "🟠"
        elif final_score >= 0.45:
            color = "🟡"
        elif final_score >= 0.30:
            color = "🟢"
        else:
            color = "🟢"
        
        st.markdown(f"### {color} Final Risk Score: {final_score:.1%}")
        st.markdown(f"**Risk Level:** {risk_level}")
        st.markdown(f"**Confidence:** {risk_assessment['confidence']:.1%}")
        
        # Display boost reasons if present
        boost_reasons = risk_assessment.get('boost_reasons', [])
        boost_amount = risk_assessment.get('boost_amount', 0.0)
        if boost_reasons and len(boost_reasons) > 0:
            boost_text = ", ".join(boost_reasons)
            st.info(f"**Boost Reason:** {boost_text} (+{boost_amount:.1%})")
    
    with col2:
        st.metric("NLP Score", f"{nlp_result['phishing_score']:.1%}")
        st.metric("Metadata Score", f"{metadata_result['metadata_score']:.1%}")
    
    with col3:
        st.metric("Graph Score", f"{graph_result['graph_score']:.1%}")
        st.metric("Recommendation", risk_assessment['risk_level'])
    
    # Recommendation
    st.info(f"**Recommendation:** {risk_assessment['recommendation']}")
    
    # Explanation
    with st.expander("📋 Detailed Explanation", expanded=True):
        st.text(risk_assessment['explanation'])
    
    # Component breakdown
    st.markdown("---")
    st.subheader("Component Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### 🤖 NLP Analysis")
        st.progress(nlp_result['phishing_score'])
        st.caption(f"Phishing Score: {nlp_result['phishing_score']:.1%}")
        st.caption(f"Urgency Score: {nlp_result['urgency_score']:.1%}")
        if nlp_result.get('phishing_keywords'):
            st.caption(f"Keywords: {', '.join(nlp_result['phishing_keywords'][:5])}")
        with st.expander("Details"):
            st.json(nlp_result)
    
    with col2:
        st.markdown("#### 🔐 Metadata Analysis")
        st.progress(1.0 - metadata_result['metadata_score'])  # Invert for display
        st.caption(f"Trust Score: {metadata_result['metadata_score']:.1%}")
        spf = metadata_result.get('spf_check', {}).get('has_spf', False)
        dmarc = metadata_result.get('dmarc_check', {}).get('has_dmarc', False)
        st.caption(f"SPF: {'✓' if spf else '✗'} | DMARC: {'✓' if dmarc else '✗'}")
        if metadata_result.get('domain_age', {}).get('age_days'):
            st.caption(f"Domain Age: {metadata_result['domain_age']['age_days']} days")
        with st.expander("Details"):
            st.json(metadata_result)
    
    with col3:
        st.markdown("#### 📊 Reputation Graph")
        st.progress(graph_result['graph_score'])
        st.caption(f"Reputation Score: {graph_result['graph_score']:.1%}")
        sender_known = graph_result.get('sender_reputation', {}).get('is_known', False)
        domain_known = graph_result.get('domain_reputation', {}).get('is_known', False)
        st.caption(f"Sender Known: {'✓' if sender_known else '✗'}")
        st.caption(f"Domain Known: {'✓' if domain_known else '✗'}")
        if graph_result.get('reputation_drift'):
            st.caption("⚠️ Reputation drift detected")
        with st.expander("Details"):
            st.json(graph_result)
    
    # Email details
    st.markdown("---")
    with st.expander("📧 Email Details"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Headers:**")
            st.json(processed.get('headers', {}))
        with col2:
            st.markdown("**Extracted Information:**")
            st.write(f"**Sender Domain:** {processed.get('sender_domain', 'N/A')}")
            st.write(f"**URLs Found:** {len(processed.get('urls', []))}")
            if processed.get('urls'):
                for url in processed['urls'][:5]:
                    st.write(f"- {url}")
            st.write(f"**Emails Found:** {len(processed.get('emails', []))}")


def display_url_results(domain, metadata_result):
    """Display URL analysis results."""
    st.markdown("---")
    st.subheader(f"Analysis Results for: {domain}")
    
    # Trust score
    trust_score = metadata_result['metadata_score']
    st.markdown(f"### Domain Trust Score: {trust_score:.1%}")
    st.progress(trust_score)
    
    # Authentication records
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### SPF Record")
        spf_check = metadata_result.get('spf_check', {})
        if spf_check.get('has_spf'):
            st.success("✓ SPF record found")
            if spf_check.get('spf_record'):
                st.caption(spf_check['spf_record'][:50] + "...")
        else:
            st.error("✗ No SPF record")
    
    with col2:
        st.markdown("#### DMARC Record")
        dmarc_check = metadata_result.get('dmarc_check', {})
        if dmarc_check.get('has_dmarc'):
            st.success(f"✓ DMARC record found")
            policy = dmarc_check.get('policy', 'none')
            st.caption(f"Policy: {policy}")
        else:
            st.error("✗ No DMARC record")
    
    with col3:
        st.markdown("#### DKIM Record")
        dkim_check = metadata_result.get('dkim_check', {})
        if dkim_check.get('has_dkim'):
            st.success("✓ DKIM record found")
        else:
            st.warning("✗ No DKIM record")
    
    # Domain information
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Domain Age")
        domain_age = metadata_result.get('domain_age', {})
        if domain_age.get('age_days'):
            age_days = domain_age['age_days']
            age_years = domain_age.get('age_years', age_days / 365.25)
            st.metric("Age", f"{age_days} days ({age_years:.2f} years)")
            if age_days < 30:
                st.warning("⚠️ Very new domain (suspicious)")
            elif age_days < 90:
                st.warning("⚠️ New domain (caution advised)")
            else:
                st.success("✓ Established domain")
        else:
            st.info("Domain age information not available")
    
    with col2:
        st.markdown("#### Domain Characteristics")
        entropy = metadata_result.get('domain_entropy', 0)
        st.metric("Entropy", f"{entropy:.2f}")
        if entropy > 0.7:
            st.warning("⚠️ High entropy (random-looking domain)")
        
        suspicious_tld = metadata_result.get('suspicious_tld', 0)
        if suspicious_tld > 0.5:
            st.error("⚠️ Suspicious TLD detected")
        else:
            st.success("✓ Normal TLD")
    
    # Detailed information
    with st.expander("📋 Detailed Metadata"):
        st.json(metadata_result)
    
    # Explanation
    st.info(f"**Analysis:** {metadata_result.get('explanation', 'No explanation available')}")


if __name__ == "__main__":
    main()
