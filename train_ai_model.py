import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib
import os

# 1. Training Data (Forensic Malicious vs Clean Patterns)
TRAINING_DATA = [
    # Malicious / Phishing / Threat
    ("Urgent: Your bank account is suspended. Click http://bit.ly/steal to verify.", "HIGH"),
    ("New login from unknown device. If this wasn't you, go to secure-login-verify.com", "HIGH"),
    ("Congratulations! You won $1000. Claim here: http://win-now.tk", "HIGH"),
    ("Download your invoice.pdf.exe from this link: http://malware.sh", "HIGH"),
    ("WhatsApp Verification Code: 123456. Do not share.", "LOW"), # Targeted but often clean
    ("Meeting at 3pm today in the conference room.", "LOW"),
    ("Hey mom, I lost my phone. Can you send 50$ to this number?", "HIGH"), # Social Engineering
    ("Verify your identity to prevent account deletion.", "HIGH"),
    ("Package delivery failed. Track at http://delivery-post.com/track", "HIGH"),
    ("Hi, how are you doing today?", "LOW"),
    ("Your appointment is confirmed for tomorrow.", "LOW")
]

def train_forensic_model():
    """Trains a simple AI model to classify text risk levels."""
    print("[AI] Initializing forensic model training...")
    
    # Extract text and labels
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    # Create ML Pipeline: Vectorize -> Classify
    model = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2))),
        ('clf', MultinomialNB())
    ])

    # Train
    model.fit(texts, labels)
    
    # Save for real-time use
    joblib.dump(model, 'forensic_ai_model.pkl')
    print("[AI] Model trained and saved as forensic_ai_model.pkl")
    return model

def load_or_train():
    if os.path.exists('forensic_ai_model.pkl'):
        return joblib.load('forensic_ai_model.pkl')
    return train_forensic_model()

if __name__ == "__main__":
    train_forensic_model()
