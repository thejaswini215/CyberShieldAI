import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Determine base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")

def train():
    print(f"Loading dataset from: {DATA_PATH}", flush=True)
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}. Please ensure the dataset is downloaded.")

    # 1. Load the public dataset
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()

    print("Dataset shape:", df.shape, flush=True)
    print("Columns:", df.columns.tolist()[:10], "... (total:", len(df.columns), ")", flush=True)

    # 2. Select URL text and target label
    # In PhiUSIIL dataset, target is 'label' (1 = legitimate, 0 = phishing)
    df = df[["URL", "label"]].dropna()
    df["URL"] = df["URL"].astype(str)
    df["label"] = df["label"].astype(int)

    print("Label distribution:", flush=True)
    print(df["label"].value_counts(), flush=True)

    X = df["URL"]
    y = df["label"]

    # 3. Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}", flush=True)

    # 4. Create the machine-learning pipeline
    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=200000
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                solver="lbfgs"
            )
        )
    ])

    # 5. Train the model
    print("Training started (character n-grams 3-5 + TF-IDF Logistic Regression)...", flush=True)
    model.fit(X_train, y_train)
    print("Training completed!", flush=True)

    # 6. Evaluate the model
    predictions = model.predict(X_test)

    print(
        "Accuracy:",
        round(accuracy_score(y_test, predictions) * 100, 2),
        "%",
        flush=True
    )

    print("\nClassification Report:", flush=True)
    print(classification_report(y_test, predictions, target_names=["Phishing (0)", "Legitimate (1)"] if set(y.unique()) == {0, 1} else None), flush=True)
    print("\nConfusion Matrix:", flush=True)
    print(confusion_matrix(y_test, predictions), flush=True)

    # 7. Save the trained model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"\nModel successfully saved to: {MODEL_PATH}", flush=True)

if __name__ == "__main__":
    train()
