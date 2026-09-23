"""
Unified High-Accuracy Feature Extraction Module for CVE Vulnerability Text & Metadata.
"""

import re
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

class CVEFeatureExtractor:
    """
    Hybrid feature extractor combining:
    1. Sublinear Word n-grams (1-2) with cybersecurity domain vocabulary.
    2. Sublinear Character n-grams (3-5) for software library names, acronyms, and version patterns.
    3. Deterministic cybersecurity threat indicators (RCE, PrivEsc, DoS, SQLi, AuthBypass, BoF).
    4. Threat intelligence priors (EPSS score, CISA KEV presence, log text length).
    """
    def __init__(self):
        self.word_tfidf = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=12000,
            sublinear_tf=True,
            stop_words="english"
        )
        self.char_tfidf = TfidfVectorizer(
            ngram_range=(3, 5),
            analyzer="char_wb",
            max_features=8000,
            sublinear_tf=True
        )

        # High-signal cybersecurity regex patterns
        self.threat_patterns = [
            re.compile(r"\b(remote\s+code\s+execution|execute\s+arbitrary\s+(code|command)|arbitrary\s+code)\b", re.I),
            re.compile(r"\b(privilege\s+escalation|gain\s+elevated|root\s+privileges|administrator\s+rights)\b", re.I),
            re.compile(r"\b(bypass\s+authentication|improper\s+authentication|unauthenticated|without\s+credentials)\b", re.I),
            re.compile(r"\b(buffer\s+overflow|heap\s+overflow|stack\s+overflow|out-of-bounds\s+(read|write)|memory\s+corruption)\b", re.I),
            re.compile(r"\b(denial\s+of\s+service|cause\s+a\s+crash|resource\s+exhaustion|infinite\s+loop|unresponsive)\b", re.I),
            re.compile(r"\b(sql\s+injection|sql\s+command|sqli)\b", re.I),
            re.compile(r"\b(cross-site\s+scripting|xss)\b", re.I),
            re.compile(r"\b(server-side\s+request\s+forgery|ssrf)\b", re.I),
            re.compile(r"\b(zero-day|in\s+the\s+wild|active(ly)?\s+exploit(ed)?)\b", re.I),
            re.compile(r"\b(network|adjacent|remote|untrusted\s+network)\b", re.I),
        ]

    def _extract_domain_signals(self, texts):
        signals = []
        for text in texts:
            t = str(text)
            flags = [1.0 if pattern.search(t) else 0.0 for pattern in self.threat_patterns]
            signals.append(flags)
        return np.array(signals, dtype=float)

    def fit(self, texts, epss_scores=None, kev_statuses=None):
        self.word_tfidf.fit(texts)
        self.char_tfidf.fit(texts)
        return self

    def transform(self, texts, epss_scores=None, kev_statuses=None):
        X_w = self.word_tfidf.transform(texts)
        X_c = self.char_tfidf.transform(texts)

        n_samples = len(texts)
        if epss_scores is None:
            epss_scores = np.zeros(n_samples)
        else:
            epss_scores = np.array(epss_scores, dtype=float)
            epss_scores = np.nan_to_num(epss_scores, nan=0.0)

        if kev_statuses is None:
            kev_statuses = np.zeros(n_samples)
        else:
            kev_statuses = np.array(kev_statuses, dtype=float)
            kev_statuses = np.nan_to_num(kev_statuses, nan=0.0)

        lengths = np.log1p([len(str(t)) for t in texts])
        domain_signals = self._extract_domain_signals(texts)

        meta = np.column_stack([epss_scores, kev_statuses, lengths, domain_signals])
        return hstack([X_w, X_c, csr_matrix(meta)]).tocsr()

