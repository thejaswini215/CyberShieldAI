import os
import sys

def test_environment():
    print("=== CyberShield AI Test Suite ===")
    
    # 1. Dataset check
    data_path = os.path.join("data", "PhiUSIIL_Phishing_URL_Dataset.csv")
    if os.path.exists(data_path):
        size_mb = os.path.getsize(data_path) / (1024 * 1024)
        print(f"[PASS] Dataset located: {data_path} ({size_mb:.2f} MB)")
    else:
        print(f"[FAIL] Dataset missing at {data_path}")

    # 2. Heuristic extraction check
    try:
        from app import extract_features, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS
        test_phish = "http://192.168.1.1/paypal-update-account/login.html"
        test_legit = "https://www.google.com"
        
        feat_p, ind_p = extract_features(test_phish)
        feat_l, ind_l = extract_features(test_legit)
        
        assert feat_p.has_ip_address == True, "Failed IP detection"
        assert len(feat_p.has_suspicious_keywords) > 0, "Failed keyword detection"
        assert feat_l.is_https == True, "Failed HTTPS check"
        assert len(ind_l) == 0, "Legitimate URL should have 0 severe indicators"
        print("[PASS] Security heuristics and feature extractor functioning correctly.")
    except Exception as e:
        print(f"[FAIL] Heuristics test error: {e}")

    # 3. Model check
    model_path = os.path.join("models", "phishing_model.joblib")
    if os.path.exists(model_path):
        try:
            import joblib
            model = joblib.load(model_path)
            test_preds = model.predict(["https://github.com", "http://login-verify-account.tk"])
            print(f"[PASS] Model loaded successfully: {model_path}")
            print(f"       Sample predictions: {test_preds}")
        except Exception as e:
            print(f"[FAIL] Model loading error: {e}")
    else:
        print(f"[INFO] Model not yet trained at {model_path}. Run 'python train_model.py' to train.")

    # 4. Spring Boot artifact check
    target_jar = os.path.join("backend", "target", "cybershield-backend-1.0.0.jar")
    target_classes = os.path.join("backend", "target", "classes", "com", "cybershield", "CyberShieldApplication.class")
    if os.path.exists(target_classes) or os.path.exists(target_jar):
        print("[PASS] Spring Boot backend compiled classes verified.")
    else:
        print("[WARN] Spring Boot target not compiled. Run 'mvn compile' inside backend/.")

    # 5. Frontend check
    fe_index = os.path.join("frontend", "index.html")
    be_static = os.path.join("backend", "src", "main", "resources", "static", "index.html")
    if os.path.exists(fe_index) and os.path.exists(be_static):
        print("[PASS] React frontend dashboard available in both frontend/ and Spring Boot static resources.")

    print("=== Verification Complete ===")

if __name__ == "__main__":
    test_environment()
