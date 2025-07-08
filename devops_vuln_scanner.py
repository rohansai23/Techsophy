# devops_vuln_scanner.py

import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ---------------------------
# 1. Simulate Vulnerability Scan Results
# ---------------------------

def mock_scan_results():
    """
    Simulates scanning results from:
      - Code repo scanning
      - Container scanning
      - Infrastructure scanning
    """
    vuln_data = []
    for i in range(30):
        vuln = {
            "id": f"VULN-{i+1}",
            "source": random.choice(["Code", "Container", "Infrastructure"]),
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "exploit_available": random.choice([0, 1]),
            "affected_assets": random.randint(1, 50),
            "fix_complexity": random.choice(["Low", "Medium", "High"]),
        }
        vuln_data.append(vuln)
    return pd.DataFrame(vuln_data)

# ---------------------------
# 2. Simple ML Model for Risk Scoring
# ---------------------------

def train_risk_model():
    """
    Trains a dummy ML model to predict HIGH_RISK vulnerabilities
    based on attributes.
    """
    # Generate mock training data
    train_data = []
    for _ in range(500):
        sev = random.choice(["Low", "Medium", "High", "Critical"])
        exploit = random.choice([0, 1])
        assets = random.randint(1, 100)
        fix_comp = random.choice(["Low", "Medium", "High"])
        # Define a simple logic for labeling
        label = 1 if (sev in ["High", "Critical"] and exploit == 1 and assets > 10) else 0
        train_data.append([sev, exploit, assets, fix_comp, label])
    
    df_train = pd.DataFrame(
        train_data, 
        columns=["severity", "exploit_available", "affected_assets", "fix_complexity", "high_risk"]
    )
    
    # Encode categorical features
    df_train_enc = pd.get_dummies(df_train, columns=["severity", "fix_complexity"])

    X_train = df_train_enc.drop("high_risk", axis=1)
    y_train = df_train_enc["high_risk"]

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)

    return model

def predict_risk(model, df_vulns):
    """
    Predicts high-risk vulnerabilities using ML model
    """
    df_input = df_vulns.copy()
    df_input_enc = pd.get_dummies(df_input, columns=["severity", "fix_complexity"])

    # Align columns with training set
    train_columns = model.feature_names_in_
    for col in train_columns:
        if col not in df_input_enc.columns:
            df_input_enc[col] = 0

    df_input_enc = df_input_enc[train_columns]

    risk_preds = model.predict(df_input_enc)
    df_vulns["high_risk"] = risk_preds
    return df_vulns

# ---------------------------
# 3. Prioritize Vulnerabilities
# ---------------------------

def prioritize_vulnerabilities(df_vulns):
    """
    Sort vulnerabilities by:
      - High risk
      - Severity
      - Affected assets
    """
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    df_vulns["severity_score"] = df_vulns["severity"].map(severity_map)

    df_sorted = df_vulns.sort_values(
        by=["high_risk", "severity_score", "affected_assets"], 
        ascending=[False, False, False]
    )
    return df_sorted

# ---------------------------
# 4. Generate Remediation Plan
# ---------------------------

def generate_remediation_plan(df_sorted):
    """
    Generates simple remediation steps
    """
    remediation_steps = []
    for _, row in df_sorted.iterrows():
        step = {
            "vuln_id": row["id"],
            "source": row["source"],
            "severity": row["severity"],
            "risk_level": "High" if row["high_risk"] == 1 else "Normal",
            "recommended_action": f"Fix {row['severity']} vulnerability in {row['source']}. Complexity: {row['fix_complexity']}."
        }
        remediation_steps.append(step)
    return remediation_steps

# ---------------------------
# MAIN FLOW
# ---------------------------

if __name__ == "__main__":
    print("=== DevOps Security Vulnerability Scanner ===")

    # 1. Mock scan
    df_vulns = mock_scan_results()
    print(f"Scanned {len(df_vulns)} vulnerabilities.\n")

    # 2. Train ML model
    model = train_risk_model()

    # 3. Predict risk
    df_scored = predict_risk(model, df_vulns)

    # 4. Prioritize
    df_prioritized = prioritize_vulnerabilities(df_scored)

    # 5. Generate remediation plan
    remediation_plan = generate_remediation_plan(df_prioritized)

    # Print results
    for item in remediation_plan:
        print(item)
