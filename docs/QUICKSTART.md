# Quick Start Guide

## Getting Started in 5 Minutes

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

**Note**: The first time you run the application, it will download transformer models (~250MB). Ensure you have internet connectivity.

### Step 2: Run the Application

```bash
streamlit run app/streamlit_app.py
```

### Step 3: Test with Sample Email

Copy and paste this sample phishing email into the "Email Analysis" tab:

```
From: security@paypal-verify.com
To: user@example.com
Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

We have detected unusual activity on your account. Your account will be 
suspended within 24 hours if you don't verify your identity immediately.

Click here to verify: http://paypal-verify.com/secure

Thank you,
PayPal Security Team
```

Click "Analyze Email" and review the results!

## Understanding the Results

### Risk Score Components

1. **NLP Score**: Based on text analysis (phishing keywords, urgency, suspicious patterns)
2. **Metadata Score**: Based on domain authentication (SPF/DKIM/DMARC) and domain age
3. **Graph Score**: Based on historical reputation and sender behavior

### Risk Levels

- **CRITICAL (≥80%)**: Block immediately
- **HIGH (60-79%)**: Quarantine for review
- **MEDIUM (40-59%)**: Flag for manual review
- **LOW (20-39%)**: Monitor but allow
- **VERY LOW (<20%)**: Appears legitimate

## Customization

### Adjusting Detection Weights

In the Streamlit sidebar, you can adjust the weights for each detection module:
- **NLP Weight**: How much to trust text analysis
- **Metadata Weight**: How much to trust domain checks
- **Graph Weight**: How much to trust historical reputation

### Programmatic Usage

See `README.md` for examples of using the modules programmatically.

## Troubleshooting

### "Model download failed"
- Check internet connection
- Try again - models are cached after first download

### "DNS resolution failed"
- Normal for domains without proper DNS records
- The system handles this gracefully

### "Memory error"
- Use DistilBERT instead of BERT (default)
- Close other applications to free RAM

## Next Steps

1. Try analyzing different types of emails
2. Experiment with weight adjustments
3. Review the detailed explanations for each analysis
4. Check the code structure in `src/` to understand how it works

