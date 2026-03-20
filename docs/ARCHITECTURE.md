# Architecture Documentation

## System Overview

PhishGuard-AI++ follows a modular architecture where each component has a specific responsibility. The system processes emails through a pipeline of analysis modules, then combines their outputs into a final risk score.

## Component Architecture

```
┌─────────────────┐
│  Email Input    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Preprocessing   │  ← Email parsing, cleaning, feature extraction
│    Module        │
└────────┬────────┘
         │
         ├──────────────────┬──────────────────┐
         ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   NLP        │  │  Metadata    │  │    Graph     │
│   Module     │  │   Module     │  │   Module     │
│              │  │              │  │              │
│ - Transformers│ │ - SPF/DKIM  │  │ - Reputation │
│ - Patterns   │  │ - WHOIS      │  │ - Drift      │
│ - Keywords   │  │ - Entropy    │  │ - History    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       └─────────────────┼──────────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │   Fusion     │
                  │   Engine     │
                  │              │
                  │ - Weighted   │
                  │ - Scoring    │
                  │ - Confidence │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Final Risk   │
                  │ Assessment   │
                  └──────────────┘
```

## Module Details

### 1. Preprocessing Module (`src/preprocessing/`)

**Purpose**: Extract and clean email content

**Key Classes**:
- `EmailProcessor`: Main processing class

**Responsibilities**:
- Parse raw email strings
- Extract headers (From, To, Subject, etc.)
- Extract body text (plain text and HTML)
- Clean and normalize text
- Extract URLs and email addresses
- Extract sender domain

**Output**: Dictionary with processed email data

### 2. NLP Module (`src/nlp_module/`)

**Purpose**: Analyze email text for phishing indicators

**Key Classes**:
- `NLPAnalyzer`: Transformer-based text analysis

**Responsibilities**:
- Detect phishing keywords
- Identify urgency patterns
- Detect suspicious language patterns
- Use transformer models (DistilBERT/BERT) for deep analysis
- Calculate phishing probability scores

**Output**: Dictionary with NLP analysis results and scores

### 3. Metadata Module (`src/metadata_module/`)

**Purpose**: Analyze domain and authentication metadata

**Key Classes**:
- `MetadataAnalyzer`: Domain and DNS analysis

**Responsibilities**:
- Check SPF records
- Check DMARC records
- Check DKIM records
- Perform WHOIS lookups for domain age
- Calculate domain entropy (Shannon entropy)
- Detect suspicious TLDs

**Output**: Dictionary with metadata analysis and trust scores

### 4. Graph Module (`src/graph_module/`)

**Purpose**: Track sender-domain relationships and reputation

**Key Classes**:
- `ReputationGraph`: Graph-based reputation tracker

**Responsibilities**:
- Maintain sender-to-domain graph
- Track historical reputation scores
- Detect reputation drift over time
- Calculate reputation scores based on history
- Persist graph data to disk

**Output**: Dictionary with graph analysis and reputation scores

### 5. Fusion Engine (`src/fusion_engine/`)

**Purpose**: Combine all signals into final risk score

**Key Classes**:
- `RiskScorer`: Hybrid risk scoring engine

**Responsibilities**:
- Weighted fusion of component scores
- Calculate confidence intervals
- Generate human-readable explanations
- Provide actionable recommendations
- Determine risk levels

**Output**: Dictionary with final risk assessment

## Data Flow

1. **Input**: Raw email string or email.Message object
2. **Preprocessing**: Extract and clean email components
3. **Parallel Analysis**: 
   - NLP analysis (text-based)
   - Metadata analysis (domain-based)
   - Graph analysis (reputation-based)
4. **Fusion**: Combine scores with weighted averaging
5. **Output**: Final risk score with explanation

## Scoring Methodology

### Component Scores

- **NLP Score**: 0.0 (legitimate) to 1.0 (phishing)
- **Metadata Score**: 0.0 (suspicious) to 1.0 (trustworthy)
- **Graph Score**: 0.0 (bad reputation) to 1.0 (good reputation)

### Fusion Formula

```
final_score = (
    nlp_weight * nlp_score +
    metadata_weight * (1 - metadata_score) +  # Invert metadata
    graph_weight * (1 - graph_score)            # Invert graph
)
```

Default weights:
- NLP: 0.4
- Metadata: 0.35
- Graph: 0.25

### Risk Level Mapping

- CRITICAL: ≥0.8
- HIGH: 0.6-0.79
- MEDIUM: 0.4-0.59
- LOW: 0.2-0.39
- VERY LOW: <0.2

## Persistence

### Graph Persistence

The reputation graph is persisted to `data/reputation_graph.json`:
- Sender-domain edges
- Historical reputation scores
- Timestamps for temporal analysis

### Model Persistence

Transformer models are cached by HuggingFace transformers library:
- Location: `~/.cache/huggingface/transformers/`
- Automatically downloaded on first use
- Cached for subsequent runs

## Extensibility Points

### Adding New Detection Modules

1. Create new module in `src/`
2. Implement `analyze(email_data)` method
3. Return dictionary with scores
4. Add to fusion engine in `RiskScorer`

### Customizing Weights

- Adjust in Streamlit UI sidebar
- Modify `RiskScorer` initialization
- Implement dynamic weight adjustment based on confidence

### Adding New Features

- **Fine-tuned Models**: Replace base transformer with phishing-specific model
- **Threat Intelligence**: Add module to check against threat feeds
- **Behavioral Analysis**: Add module for user behavior patterns
- **Image Analysis**: Add module for email image analysis

## Performance Considerations

### Caching

- Analyzer instances are cached in Streamlit (`@st.cache_resource`)
- Transformer models are loaded once and reused
- Graph data is loaded from disk on startup

### Optimization Opportunities

- Async DNS queries
- Batch processing for multiple emails
- Model quantization for faster inference
- Graph database for large-scale deployments

## Security Considerations

### Input Validation

- Email parsing handles malformed input gracefully
- DNS queries have timeouts to prevent hanging
- WHOIS lookups handle restricted domains

### Data Privacy

- Email content is processed in-memory
- No external API calls for email content
- Graph data stored locally

## Testing Strategy

### Unit Tests

- Test each module independently
- Mock external dependencies (DNS, WHOIS)
- Test edge cases (empty input, malformed emails)

### Integration Tests

- Test full pipeline end-to-end
- Test with sample emails
- Verify score consistency

### Performance Tests

- Measure processing time
- Test with large emails
- Profile memory usage

