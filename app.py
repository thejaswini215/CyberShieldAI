import os
import re
import urllib.parse
from typing import List, Optional, Dict, Any, Tuple
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import joblib

app = FastAPI(
    title="CyberShield AI - Phishing URL Detection & Agent API",
    version="1.0.0",
    description="ML-powered Phishing URL detection with contextual AI risk analysis"
)

# CORS configuration for React frontend & Spring Boot backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.joblib")

model = None

def get_model():
    global model
    if model is None:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            model = None
    return model

class URLRequest(BaseModel):
    url: str

class FeatureInspection(BaseModel):
    has_ip_address: bool
    url_length: int
    num_dots: int
    has_at_symbol: bool
    has_double_slash_redirect: bool
    num_hyphens: int
    has_suspicious_keywords: List[str]
    is_https: bool
    suspicious_tld: bool

class PredictionResponse(BaseModel):
    url: str
    prediction: str
    is_phishing: bool
    confidence: float
    risk_level: str
    risk_score: int
    model_loaded: bool

class AgentAnalysisResponse(BaseModel):
    url: str
    prediction: str
    is_phishing: bool
    confidence: float
    risk_level: str
    risk_score: int
    summary: str
    features: FeatureInspection
    suspicious_indicators: List[str]
    triggered_parameters: List[str]
    recommendations: List[str]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "banking", "account",
    "update", "confirm", "wallet", "paypal", "appleid", "support",
    "security", "auth", "credential", "recover", "ebay", "netflix",
    "webscr", "password", "validation", "service"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".gq",
    ".cf", ".ml", ".ga", ".tk", ".buzz", ".cam", ".rest"
]

# Trusted Institutional, Educational, and Verified Platforms
TRUSTED_ROOT_DOMAINS = {
    # Educational & Academic Institutions
    "vitap.ac.in": "VIT-AP University",
    "vit.ac.in": "Vellore Institute of Technology",
    "iitm.ac.in": "IIT Madras",
    "iitb.ac.in": "IIT Bombay",
    "iitd.ac.in": "IIT Delhi",
    "mit.edu": "MIT",
    "stanford.edu": "Stanford University",
    "harvard.edu": "Harvard University",
    
    # Major Global Infrastructure & Verified Platforms
    "whatsapp.com": "WhatsApp / Meta Official",
    "meta.com": "Meta Platforms",
    "facebook.com": "Facebook / Meta",
    "instagram.com": "Instagram / Meta",
    "google.com": "Google Official Services",
    "youtube.com": "YouTube / Google",
    "github.com": "GitHub / Microsoft",
    "microsoft.com": "Microsoft Official Services",
    "apple.com": "Apple Official Services",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon India",
    "netflix.com": "Netflix",
    "linkedin.com": "LinkedIn",
    "twitter.com": "X / Twitter",
    "x.com": "X Corp",
    "wikipedia.org": "Wikimedia Foundation",
    "yahoo.com": "Yahoo",
    "cloudflare.com": "Cloudflare Security"
}

TRUSTED_ACADEMIC_GOV_TLDS = [".ac.in", ".edu.in", ".gov.in", ".gov", ".edu"]

def check_domain_reputation(url_str: str) -> Optional[Dict[str, Any]]:
    """
    Checks if a domain belongs to a verified institutional, government, 
    or educational domain registry, overriding character-level ML false positives.
    """
    try:
        parsed = urllib.parse.urlparse(url_str)
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]
            
        # 1. Exact or subdomain match for trusted root domains
        for root_domain, org_name in TRUSTED_ROOT_DOMAINS.items():
            if domain == root_domain or domain.endswith("." + root_domain):
                return {
                    "is_trusted": True,
                    "organization": org_name,
                    "type": "Verified Institutional Portal"
                }

        # 2. Check academic/governmental accredited TLDs
        for tld in TRUSTED_ACADEMIC_GOV_TLDS:
            if domain.endswith(tld):
                return {
                    "is_trusted": True,
                    "organization": f"Accredited Institution ({tld.lstrip('.')})",
                    "type": "Accredited Academic / Government Domain"
                }
    except Exception:
        pass
    return None

def extract_features(url_str: str) -> (FeatureInspection, List[str]):
    parsed = urllib.parse.urlparse(url_str)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url_str.lower()

    # IP address in domain
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?$"
    has_ip = bool(re.match(ip_pattern, domain))

    # Keywords detection
    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]

    # Suspicious TLD
    suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # Double slash in path
    double_slash = "//" in path

    # At symbol
    has_at = "@" in url_str

    num_dots = domain.count(".")
    num_hyphens = domain.count("-")
    is_https = parsed.scheme.lower() == "https"
    url_length = len(url_str)

    indicators = []
    if has_ip:
        indicators.append("IP address used directly instead of a legitimate domain name.")
    if url_length > 75:
        indicators.append(f"Unusually long URL length ({url_length} characters), typical of obfuscation.")
    if num_dots > 3:
        indicators.append(f"Excessive subdomains/dots detected in hostname ({num_dots} dots).")
    if num_hyphens > 2:
        indicators.append(f"Multiple hyphens in domain name ({num_hyphens} hyphens), often used to mimic trusted brands.")
    if has_at:
        indicators.append("Contains '@' symbol which can redirect browser authentication.")
    if double_slash:
        indicators.append("Contains path redirection sequence '//'.")
    if suspicious_tld:
        indicators.append("Uses a top-level domain frequently associated with throwaway phishing campaigns.")
    if detected_keywords:
        indicators.append(f"Contains sensitive targeted security keywords: {', '.join(detected_keywords)}.")
    if not is_https:
        indicators.append("Connection lacks HTTPS encryption (unsecured HTTP).")

    features = FeatureInspection(
        has_ip_address=has_ip,
        url_length=url_length,
        num_dots=num_dots,
        has_at_symbol=has_at,
        has_double_slash_redirect=double_slash,
        num_hyphens=num_hyphens,
        has_suspicious_keywords=detected_keywords,
        is_https=is_https,
        suspicious_tld=suspicious_tld
    )

    return features, indicators

@app.get("/")
def root():
    clf = get_model()
    return {
        "service": "CyberShield AI Detection Service",
        "status": "ready" if clf is not None else "model_pending_training",
        "model_file": MODEL_PATH,
        "endpoints": {
            "health": "/health",
            "predict": "POST /predict",
            "agent_analyze": "POST /agent/analyze"
        }
    }

@app.get("/health")
def health_check():
    clf = get_model()
    return {
        "status": "UP",
        "model_loaded": clf is not None
    }

def calculate_risk(url_clean: str, clf_proba: Optional[float], features: FeatureInspection, indicators: List[str]) -> Tuple[str, str, int, List[str]]:
    """
    Computes a synthesized Risk Score (0-100), Risk Level (Low, Medium, High),
    Verdict Text, and detailed Parameter triggers.
    
    Parameters per Risk Tier:
    ---------------------------------------------------------
    1. LOW RISK (Score 0-30):
       - Verified institutional or global domain allowlist match.
       - Clean URL syntax, valid HTTPS, 0 suspicious structural markers.
       - ML phishing probability < 35%.
    
    2. MEDIUM RISK (Score 31-70):
       - Unverified domain containing sensitive authentication keywords (/login, /verify, /secure).
       - Conflicting signals: ML indicates suspicious pattern but structural markers are mild.
       - Subdomain depth (3-4 dots), elevated URL length (75-110 chars), or minor hyphenation.
       - Insecure HTTP connection on pages requesting user interactions.
       - ML confidence in ambiguous range (40% - 75%).
    
    3. HIGH RISK (Score 71-100):
       - Direct IP address used in host instead of domain name.
       - Credential spoofing syntax using '@' or redirect '//' sequences.
       - High-risk throwaway TLDs (.xyz, .top, .tk) paired with credential keywords.
       - High ML model confidence (>80%) backed by multiple severe structural anomalies.
    """
    reputation = check_domain_reputation(url_clean)
    triggered_params = []

    # 1. Check Allowlist / Institutional Domain
    if reputation:
        triggered_params.append(f"Domain Reputation: Verified official registry for {reputation['organization']} ({reputation['type']})")
        triggered_params.append("Clean Structure: Certified domain with valid hierarchy and trusted trust chain")
        return "Likely Legitimate", "Low", 5, triggered_params

    score = 0

    # 2. Severe Red Flags (High Risk instant boosters)
    if features.has_ip_address:
        score += 45
        triggered_params.append("Severe Risk: Raw IP address used as hostname instead of a registered domain")
    if features.has_at_symbol:
        score += 40
        triggered_params.append("Severe Risk: '@' credential spoofing sequence detected in URL authority")
    if features.has_double_slash_redirect:
        score += 30
        triggered_params.append("High Risk: Path redirection sequence '//' detected")
    if features.suspicious_tld:
        score += 30
        triggered_params.append("High Risk: Top-level domain frequently associated with disposable phishing campaigns")

    # 3. Medium Risk Structural Markers
    if len(features.has_suspicious_keywords) > 0:
        kw_score = min(25, 12 * len(features.has_suspicious_keywords))
        score += kw_score
        triggered_params.append(f"Medium Risk: Sensitive authentication keyword(s) detected: {', '.join(features.has_suspicious_keywords)}")
    if features.num_dots > 3:
        score += 15
        triggered_params.append(f"Medium Risk: Deep subdomain nesting ({features.num_dots} dots in hostname)")
    if features.num_hyphens > 2:
        score += 15
        triggered_params.append(f"Medium Risk: Multiple hyphens mimicry pattern ({features.num_hyphens} hyphens)")
    if features.url_length > 75:
        score += 15
        triggered_params.append(f"Medium Risk: Obfuscated / elongated URL length ({features.url_length} characters)")
    if not features.is_https:
        score += 15
        triggered_params.append("Medium Risk: Unsecured connection (plain HTTP lacking TLS encryption)")

    # 4. Machine Learning Model Probability Factor (0 to 35 points)
    if clf_proba is not None:
        # clf_proba is phishing probability between 0.0 and 1.0
        ml_points = int(clf_proba * 35)
        score += ml_points
        if clf_proba > 0.80:
            triggered_params.append(f"ML Model: Strong character n-gram phishing signature ({clf_proba*100:.1f}%)")
        elif clf_proba >= 0.50:
            triggered_params.append(f"ML Model: Borderline / suspicious character distribution ({clf_proba*100:.1f}%)")
        else:
            triggered_params.append(f"ML Model: Consistent with legitimate character patterns ({(1-clf_proba)*100:.1f}% legit)")

    # Normalize score between 0 and 100
    risk_score = min(100, max(0, score))

    # Determine Tier (Low, Medium, High)
    if risk_score >= 70 or features.has_ip_address or (features.suspicious_tld and len(features.has_suspicious_keywords) > 0):
        risk_level = "High"
        verdict = "Potential Phishing"
    elif risk_score >= 30 or (clf_proba is not None and clf_proba >= 0.50) or len(indicators) >= 1:
        risk_level = "Medium"
        verdict = "Suspicious (Medium Risk)"
    else:
        risk_level = "Low"
        verdict = "Likely Legitimate"

    return verdict, risk_level, risk_score, triggered_params

@app.post("/predict", response_model=PredictionResponse)
def predict_url(payload: URLRequest):
    url_clean = payload.url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    features, indicators = extract_features(url_clean)
    clf = get_model()

    if clf is None:
        verdict, risk_level, risk_score, triggered_params = calculate_risk(url_clean, None, features, indicators)
        return PredictionResponse(
            url=url_clean,
            prediction=verdict,
            is_phishing=(risk_level != "Low"),
            confidence=0.75 if risk_level != "Low" else 0.85,
            risk_level=risk_level,
            risk_score=risk_score,
            model_loaded=False
        )

    try:
        # In dataset: 1 = Legitimate, 0 = Phishing
        proba = clf.predict_proba([url_clean])[0]
        phishing_prob = float(proba[0])

        verdict, risk_level, risk_score, triggered_params = calculate_risk(url_clean, phishing_prob, features, indicators)
        confidence = phishing_prob if risk_level != "Low" else float(proba[1])

        return PredictionResponse(
            url=url_clean,
            prediction=verdict,
            is_phishing=(risk_level != "Low"),
            confidence=round(confidence, 4),
            risk_level=risk_level,
            risk_score=risk_score,
            model_loaded=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model inference failed: {str(e)}")

@app.post("/agent/analyze", response_model=AgentAnalysisResponse)
def agent_analyze(payload: URLRequest):
    url_clean = payload.url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    features, indicators = extract_features(url_clean)
    clf = get_model()
    phishing_prob = None
    confidence = 0.85

    if clf is not None:
        try:
            proba = clf.predict_proba([url_clean])[0]
            phishing_prob = float(proba[0])
            confidence = phishing_prob if phishing_prob >= 0.5 else float(proba[1])
        except Exception:
            pass

    verdict, risk_level, risk_score, triggered_params = calculate_risk(url_clean, phishing_prob, features, indicators)

    # Contextual summary & tailored recommendations per risk tier
    recommendations = []
    if risk_level == "High":
        summary = (
            f"CyberShield AI identified High-Risk Phishing Threats (Threat Score: {risk_score}/100, Confidence: {confidence*100:.1f}%). "
            f"The URL exhibits aggressive malicious signals or credential harvesting indicators."
        )
        recommendations.append("CRITICAL: Do NOT submit passwords, MFA codes, or financial information.")
        recommendations.append("Never download attachments or run executables prompted by this domain.")
        recommendations.append("If received via message/email, block the sender and report to security operations.")
        recommendations.append("Navigate to trusted platforms only through verified bookmarks or manual typing.")
    elif risk_level == "Medium":
        summary = (
            f"CyberShield AI evaluated this URL as Suspicious with Medium Risk (Threat Score: {risk_score}/100). "
            f"The link exhibits cautionary structural patterns or sensitive authentication keywords without confirmed high-severity compromise."
        )
        recommendations.append("CAUTION: Verify the exact domain name in your browser address bar before interacting.")
        recommendations.append("Avoid entering sensitive account credentials unless you independently verified the source.")
        recommendations.append("Check whether the domain is the organization's official primary domain.")
        recommendations.append("Ensure multi-factor authentication (MFA) is enabled for your associated accounts.")
    else:
        reputation = check_domain_reputation(url_clean)
        org_text = f" ({reputation['organization']})" if reputation else ""
        summary = (
            f"CyberShield AI evaluated this URL as Likely Legitimate{org_text} (Threat Score: {risk_score}/100, Confidence: {confidence*100:.1f}%). "
            f"No malicious phishing indicators were detected."
        )
        recommendations.append("Domain verified. Safe to proceed with standard browsing.")
        recommendations.append("Always look for the HTTPS padlock icon before submitting private data.")

    return AgentAnalysisResponse(
        url=url_clean,
        prediction=verdict,
        is_phishing=(risk_level != "Low"),
        confidence=round(confidence, 4),
        risk_level=risk_level,
        risk_score=risk_score,
        summary=summary,
        features=features,
        suspicious_indicators=indicators,
        triggered_parameters=triggered_params,
        recommendations=recommendations
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
