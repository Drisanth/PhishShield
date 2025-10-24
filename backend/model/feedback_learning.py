import json
import os
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

class FeedbackLearningSystem:
    def __init__(self, feedback_file="feedback.json", model_path="model/feedback_model.pkl"):
        self.feedback_file = feedback_file
        self.model_path = model_path
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.model = LogisticRegression(random_state=42)
        self.is_trained = False
        
    def load_feedback_data(self):
        """Load feedback data from JSON file"""
        if not os.path.exists(self.feedback_file):
            return []
        
        with open(self.feedback_file, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    
    def prepare_training_data(self):
        """Prepare training data from feedback"""
        feedback_data = self.load_feedback_data()
        
        if len(feedback_data) < 10:  # Need minimum samples for training
            return None, None
        
        texts = []
        labels = []
        
        for feedback in feedback_data:
            email_data = feedback.get('emailData', {})
            analysis_result = feedback.get('analysisResult', {})
            correct = feedback.get('correct', True)
            
            # Extract text content
            text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
            texts.append(text)
            
            # Create label based on feedback
            # If user says "correct" and verdict was phishing, label as 1 (phishing)
            # If user says "incorrect" and verdict was phishing, label as 0 (not phishing)
            verdict = analysis_result.get('verdict', '')
            if 'Phishing' in verdict or 'Suspicious' in verdict:
                label = 1 if correct else 0
            else:
                label = 0 if correct else 1
            
            labels.append(label)
        
        return texts, labels
    
    def train_model(self):
        """Train the model with feedback data"""
        texts, labels = self.prepare_training_data()
        
        if texts is None or len(texts) < 10:
            print("Not enough feedback data for training. Need at least 10 samples.")
            return False
        
        # Vectorize texts
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained with {len(texts)} samples")
        print(f"Accuracy: {accuracy:.3f}")
        print(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        
        # Save model
        self.save_model()
        self.is_trained = True
        
        return True
    
    def save_model(self):
        """Save trained model and vectorizer"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'trained_at': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, self.model_path)
        print(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load pre-trained model"""
        if not os.path.exists(self.model_path):
            return False
        
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data['model']
            self.vectorizer = model_data['vectorizer']
            self.is_trained = True
            print(f"Model loaded from {self.model_path}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict_with_feedback_model(self, text):
        """Predict using feedback-trained model"""
        if not self.is_trained:
            if not self.load_model():
                return 0.5, "Model not trained"
        
        try:
            X = self.vectorizer.transform([text])
            probability = self.model.predict_proba(X)[0][1]  # Probability of phishing
            return float(probability), "Feedback model prediction"
        except Exception as e:
            return 0.5, f"Prediction error: {e}"
    
    def get_feedback_stats(self):
        """Get statistics about feedback data"""
        feedback_data = self.load_feedback_data()
        
        if not feedback_data:
            return {"total_feedback": 0, "accuracy": 0, "recent_feedback": []}
        
        total = len(feedback_data)
        correct_count = sum(1 for f in feedback_data if f.get('correct', False))
        accuracy = correct_count / total if total > 0 else 0
        
        # Recent feedback (last 10)
        recent = feedback_data[-10:] if len(feedback_data) > 10 else feedback_data
        
        return {
            "total_feedback": total,
            "accuracy": round(accuracy, 3),
            "recent_feedback": recent
        }

# Global instance
feedback_learner = FeedbackLearningSystem()
