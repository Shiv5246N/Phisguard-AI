# 🛡️ PhishGuard AI: Adaptive Hybrid System for Zero-Day Email Phishing Detection and Risk Intelligence

## Overview

PhishGuard AI is a hybrid machine learning system that combines NLP, metadata analysis, and graph-based intelligence to detect zero-day phishing emails in real-time. The system integrates with Gmail via IMAP/SMTP to fetch emails, analyze them using advanced AI models, and automatically send alerts when high-risk phishing attempts are detected.

### Key Capabilities

- **AI-Based Zero-Day Phishing Detection**: Uses transformer models (DistilBERT/BERT) to identify phishing patterns that traditional signature-based systems miss
- **Metadata Analysis**: Validates SPF, DKIM, and DMARC records to verify email authenticity
- **Risk Fusion Scoring**: Combines multiple detection signals using weighted fusion for accurate risk assessment
- **SMTP Alerting System**: Automatically sends alerts to designated recipients when phishing is detected
- **Live Streamlit Dashboard**: Interactive web interface for real-time email analysis
- **Real-Time Gmail Monitoring**: Fetches and analyzes the latest emails from Gmail inbox

## System Architecture

### Architecture Flow

```
Gmail Inbox (IMAP)
     ↓
Email Integration (Fetch & Parse)
     ↓
Hybrid AI Engine (NLP + Metadata + Graph)
     ↓
Risk Fusion & Scoring
     ↓
SMTP Alert Sender → Receiver
     ↓
Logs → logs/email_logs.csv
```

### Core Modules

#### 1. 📧 Email Integration Module (`src/email_integration/`)

**Purpose**: Connects to Gmail via IMAP/SMTP for email fetching and alerting

**Features**:
- Secure IMAP connection (port 993, SSL) to fetch emails
- SMTP integration (port 465, SSL) for sending alerts
- Fetches latest emails from inbox
- Extracts plain-text body (ignores HTML and attachments)
- Logs all analyzed emails to CSV

**Key Functions**:
- `fetch_latest_emails(count=5)`: Fetches the latest N emails from Gmail
- `send_alert(subject, message)`: Sends phishing alerts via SMTP

#### 2. 🧠 NLP Analysis Module (`src/nlp_module/`)

**Purpose**: Analyzes email text for phishing indicators using transformer models

**Features**:
- Transformer-based text analysis (DistilBERT/BERT)
- Phishing keyword detection
- Urgency pattern identification
- Social engineering indicator detection
- Suspicious language pattern analysis

**Output**: Phishing probability score (0-1) with detailed explanations

#### 3. 🔐 Metadata Analysis Module (`src/metadata_module/`)

**Purpose**: Analyzes domain and email authentication metadata

**Features**:
- SPF record validation
- DKIM record checking
- DMARC policy validation
- Domain age calculation (WHOIS lookup)
- Domain entropy calculation (detects random-looking domains)
- Suspicious TLD detection

**Output**: Trust score (0-1) based on domain reputation and authentication

#### 4. 📊 Graph-based Reputation Tracker (`src/graph_module/`)

**Purpose**: Tracks sender-domain relationships and historical reputation

**Features**:
- Sender-domain relationship graph (NetworkX)
- Historical reputation tracking
- Reputation drift detection
- Temporal behavior analysis
- Persistent storage (JSON)

**Output**: Reputation score (0-1) based on historical interactions

#### 5. ⚙️ Fusion Engine (`src/fusion_engine/`)

**Purpose**: Combines all detection signals into final risk score

**Features**:
- Weighted fusion of component scores
- Confidence interval calculation
- Human-readable explanations
- Actionable recommendations (BLOCK/QUARANTINE/REVIEW/MONITOR/ALLOW)
- Risk level classification

**Output**: Final risk assessment with detailed breakdown

## Quick Start Guide

### Prerequisites

- Python 3.8 or higher
- Gmail account with App Password enabled (for IMAP/SMTP access)
- Internet connection (for model downloads and DNS queries)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd PhishGuard-AI++
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   
   Create a `.env` file in the project root:
   ```env
   SMTP_EMAIL=your-email@gmail.com
   SMTP_PASS=your-app-password
   ALERT_RECEIVER=alert-receiver@gmail.com
   ```
   
   **Note**: For Gmail, you'll need to generate an App Password:
   - Go to Google Account → Security → 2-Step Verification → App Passwords
   - Generate a password for "Mail" and use it as `SMTP_PASS`

4. **Run the Streamlit application:**
   ```bash
   streamlit run app/streamlit_app.py
   ```

   The application will open in your browser at `http://localhost:8501`

### Testing Email Integration

Run the test script to analyze the latest 5 emails from your Gmail inbox:

```bash
python test_email_integration.py
```

This will:
- Connect to Gmail IMAP
- Fetch the 5 latest emails
- Analyze each using PhishGuard AI
- Send alerts for emails with risk > 60%
- Log results to `logs/email_logs.csv`

## Feature Highlights

### 🎯 AI-Based Zero-Day Phishing Detection

PhishGuard AI uses advanced transformer models to detect phishing patterns that traditional signature-based systems miss. The NLP module analyzes:
- Linguistic manipulation techniques
- Social engineering patterns
- Urgency indicators
- Suspicious language patterns

### 🔐 Metadata Analysis (SPF, DKIM, DMARC)

The metadata module validates email authentication records:
- **SPF**: Verifies sender authorization
- **DKIM**: Validates email integrity
- **DMARC**: Checks domain-based message authentication

### 📊 Risk Fusion Scoring

The fusion engine combines multiple signals:
- **NLP Score**: Text-based phishing probability
- **Metadata Score**: Domain trustworthiness
- **Graph Score**: Historical reputation

Default weights:
- NLP: 45%
- Metadata: 35%
- Graph: 20%

### 📧 SMTP Alerting System

When a high-risk email is detected (risk > 60%), the system:
- Automatically sends an alert email to the configured receiver
- Includes risk score, sender information, and email preview
- Logs the alert in `logs/email_logs.csv`

### 🖥️ Live Streamlit Dashboard

Interactive web interface featuring:
- **Email Analysis Tab**: Paste emails for real-time analysis
- **URL Analysis Tab**: Analyze domains for phishing indicators
- **About Tab**: System information and documentation
- **Configurable Weights**: Adjust detection module weights in real-time
- **Detailed Results**: Component breakdowns and explanations

### 📈 Real-Time Gmail Monitoring

The email integration module can:
- Fetch latest emails from Gmail inbox
- Analyze multiple emails in batch
- Process emails automatically
- Log all analyses for tracking

## Project Structure

```
PhishGuard-AI/
├── app/
│   └── streamlit_app.py          # Streamlit web application
├── data/
│   └── reputation_graph.json     # Graph persistence (auto-created)
├── docs/
│   ├── ARCHITECTURE.md            # Detailed architecture docs
│   └── QUICKSTART.md              # Quick start guide
├── logs/
│   └── email_logs.csv             # Email analysis logs
├── models/                        # Placeholder for trained models
├── src/
│   ├── email_integration/         # Gmail IMAP/SMTP integration
│   │   ├── smtp_client.py         # Email fetching and alerting
│   │   └── email_logger.py        # CSV logging
│   ├── preprocessing/              # Email preprocessing
│   │   └── email_processor.py
│   ├── nlp_module/                # NLP analysis
│   │   └── nlp_analyzer.py
│   ├── metadata_module/           # Domain & DNS analysis
│   │   └── metadata_analyzer.py
│   ├── graph_module/              # Reputation tracking
│   │   └── reputation_graph.py
│   └── fusion_engine/             # Risk scoring
│       └── risk_scorer.py
├── tests/                         # Unit tests
├── .env                           # Environment variables (not in repo)
├── .gitignore
├── requirements.txt
├── test_email_integration.py      # Email integration test script
└── README.md                      # This file
```

## Risk Levels

The system classifies emails into five risk levels:

- **CRITICAL** (≥75%): Highly likely phishing - **BLOCK**
- **HIGH** (60-74%): Strong indicators - **QUARANTINE**
- **MEDIUM** (45-59%): Some suspicious indicators - **REVIEW**
- **LOW** (25-44%): Low risk - **MONITOR**
- **SAFE** (<25%): Appears legitimate - **ALLOW**

## Configuration

### Environment Variables (.env)

```env
SMTP_EMAIL=your-email@gmail.com
SMTP_PASS=your-app-password
ALERT_RECEIVER=alert-receiver@gmail.com
```

### Adjusting Detection Weights

You can adjust detection weights in the Streamlit sidebar or programmatically:

```python
from src.fusion_engine import RiskScorer

risk_scorer = RiskScorer(
    nlp_weight=0.45,      # NLP analysis weight
    metadata_weight=0.35, # Metadata analysis weight
    graph_weight=0.20     # Graph analysis weight
)
```

## Usage Examples

### Programmatic Usage

```python
from src.preprocessing import EmailProcessor
from src.nlp_module import NLPAnalyzer
from src.metadata_module import MetadataAnalyzer
from src.graph_module import ReputationGraph
from src.fusion_engine import RiskScorer

# Initialize components
processor = EmailProcessor()
nlp_analyzer = NLPAnalyzer()
metadata_analyzer = MetadataAnalyzer()
reputation_graph = ReputationGraph(persistence_file='data/reputation_graph.json')
risk_scorer = RiskScorer()

# Process email
email_text = """From: suspicious@example.com
Subject: Urgent: Verify Your Account
Body: Click here to verify..."""

processed = processor.process_email(email_text)

# Run analyses
nlp_result = nlp_analyzer.analyze(processed)
metadata_result = metadata_analyzer.analyze(processed)
graph_result = reputation_graph.analyze(processed, nlp_result['phishing_score'])

# Get final risk score
risk_assessment = risk_scorer.score(nlp_result, metadata_result, graph_result)

print(f"Risk Level: {risk_assessment['risk_level']}")
print(f"Final Score: {risk_assessment['final_score']:.1%}")
print(f"Recommendation: {risk_assessment['recommendation']}")
```

### Email Integration Usage

```python
from src.email_integration import fetch_latest_emails, send_alert, log_email_analysis

# Fetch latest 5 emails
emails = fetch_latest_emails(count=5)

# Analyze each email
for subject, sender, body in emails:
    # ... perform analysis ...
    risk_score = 0.85  # Example
    
    # Send alert if high risk
    if risk_score > 0.6:
        send_alert(
            f"PhishGuard Alert: {subject}",
            f"Suspicious email from {sender}\nRisk: {risk_score*100:.1f}%"
        )
    
    # Log analysis
    log_email_analysis(sender, subject, risk_score, alert_sent=True)
```

## Technical Details

### NLP Analysis

- Uses HuggingFace transformers (DistilBERT/BERT)
- Detects phishing keywords, urgency patterns, and suspicious language
- Provides confidence scores for predictions

### Metadata Analysis

- DNS record validation (SPF, DMARC, DKIM)
- WHOIS lookups for domain age
- Shannon entropy calculation for domain names
- TLD reputation checking

### Graph Analysis

- NetworkX-based directed graph (sender → domain)
- Temporal reputation tracking
- Reputation drift detection
- Persistent storage (JSON)

### Risk Scoring

- Weighted fusion of component scores
- Confidence interval calculation
- Explainable AI with detailed explanations

## Troubleshooting

### Common Issues

1. **Model download fails**: The first run downloads transformer models (~250MB). Ensure internet connectivity.

2. **Gmail connection errors**: 
   - Verify App Password is correctly set in `.env`
   - Check that "Less secure app access" is enabled (or use App Password)
   - Ensure IMAP is enabled in Gmail settings

3. **DNS resolution errors**: Some DNS queries may timeout. This is normal for domains without proper DNS records.

4. **WHOIS lookup failures**: Some domains have restricted WHOIS data. The system handles this gracefully.

5. **Memory usage**: Large transformer models require significant RAM. Consider using DistilBERT instead of BERT for lower memory usage.

## Developer Information

**Developer:** Shivang Raj Saxena  
**Contact:** [shivangrajsaxena1403@gmail.com](mailto:shivangrajsaxena1403@gmail.com)

Developed by Sunil Prajapat as part of a patent-ready AI cybersecurity project, **PhishGuard AI: Adaptive Hybrid System for Zero-Day Email Phishing Detection and Risk Intelligence**.

## License

© 2026 PhishGuard AI | All Rights Reserved | Contact: sunilprajapat2907@gmail.com

This project is for patent demonstration purposes. All rights reserved.

---

**Project Status**: ✅ Complete and Ready for Demonstration
