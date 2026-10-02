import joblib
import pandas as pd

model = joblib.load("model.pkl")


def predict_attack(features):
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]

    confidence = max(probabilities)

    return prediction, confidence