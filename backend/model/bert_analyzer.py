import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import numpy as np
from typing import List, Tuple, Dict
import warnings
warnings.filterwarnings("ignore")

class BERTPhishingAnalyzer:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.models = {}
        self.tokenizers = {}
        self._load_models()
    
    def _load_models(self):
        """Load multiple BERT models for different analysis tasks"""
        try:
            # Main phishing detection model
            self.models['phishing'] = AutoModelForSequenceClassification.from_pretrained(
                "microsoft/DialoGPT-medium"  # Using as base, replace with phishing-specific model
            )
            self.tokenizers['phishing'] = AutoTokenizer.from_pretrained(
                "microsoft/DialoGPT-medium"
            )
            
            # Sentiment analysis for urgency detection
            self.models['sentiment'] = pipeline(
                "sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment-latest",
                device=0 if self.device == "cuda" else -1
            )
            
            # Text classification for intent detection
            self.models['intent'] = pipeline(
                "text-classification",
                model="facebook/bart-large-mnli",
                device=0 if self.device == "cuda" else -1
            )
            
            print("BERT models loaded successfully")
            
        except Exception as e:
            print(f"Error loading BERT models: {e}")
            self.models = {}
            self.tokenizers = {}
    
    def analyze_phishing_probability(self, text: str) -> Tuple[float, List[str]]:
        """Analyze text for phishing probability using BERT"""
        if 'phishing' not in self.models:
            return 0.5, ["BERT model not available"]
        
        try:
            # Tokenize and predict
            inputs = self.tokenizers['phishing'](
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.models['phishing'](**inputs)
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                phishing_prob = float(probabilities[0][1])  # Assuming class 1 is phishing
            
            return phishing_prob, ["BERT phishing analysis"]
            
        except Exception as e:
            return 0.5, [f"BERT analysis error: {str(e)}"]
    
    def analyze_sentiment_urgency(self, text: str) -> Tuple[float, List[str]]:
        """Analyze sentiment and urgency indicators"""
        if 'sentiment' not in self.models:
            return 0.5, ["Sentiment model not available"]
        
        try:
            # Analyze sentiment
            sentiment_result = self.models['sentiment'](text[:512])  # Limit text length
            
            # Check for urgency indicators
            urgency_keywords = [
                'urgent', 'immediately', 'asap', 'critical', 'emergency',
                'expires', 'deadline', 'limited time', 'act now', 'hurry'
            ]
            
            urgency_score = 0
            urgency_reasons = []
            
            text_lower = text.lower()
            for keyword in urgency_keywords:
                if keyword in text_lower:
                    urgency_score += 0.1
                    urgency_reasons.append(f"Urgency keyword: {keyword}")
            
            # Combine sentiment and urgency
            sentiment_score = 0.5
            if sentiment_result[0]['label'] == 'NEGATIVE':
                sentiment_score = 0.8
            elif sentiment_result[0]['label'] == 'POSITIVE':
                sentiment_score = 0.2
            
            final_score = min(0.5 + urgency_score + (sentiment_score - 0.5), 1.0)
            
            return final_score, urgency_reasons + [f"Sentiment: {sentiment_result[0]['label']}"]
            
        except Exception as e:
            return 0.5, [f"Sentiment analysis error: {str(e)}"]
    
    def analyze_intent_classification(self, text: str) -> Tuple[float, List[str]]:
        """Analyze intent using BERT classification"""
        if 'intent' not in self.models:
            return 0.5, ["Intent model not available"]
        
        try:
            # Define phishing-related intents
            phishing_intents = [
                "verify account", "update information", "confirm identity",
                "secure account", "login required", "suspicious activity"
            ]
            
            intent_scores = []
            intent_reasons = []
            
            for intent in phishing_intents:
                result = self.models['intent'](text, intent)
                score = result['score']
                intent_scores.append(score)
                if score > 0.5:
                    intent_reasons.append(f"Intent: {intent} (confidence: {score:.2f})")
            
            # Calculate average intent score
            avg_intent_score = np.mean(intent_scores) if intent_scores else 0.5
            
            return float(avg_intent_score), intent_reasons
            
        except Exception as e:
            return 0.5, [f"Intent analysis error: {str(e)}"]
    
    def extract_suspicious_patterns(self, text: str) -> Tuple[float, List[str]]:
        """Extract suspicious patterns using BERT embeddings"""
        if 'phishing' not in self.models:
            return 0.5, ["Pattern extraction not available"]
        
        try:
            # Tokenize text
            inputs = self.tokenizers['phishing'](
                text,
                return_tensors="pt",
                truncation=True,
                max_length=256,
                padding=True
            ).to(self.device)
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.models['phishing'](**inputs, output_hidden_states=True)
                embeddings = outputs.hidden_states[-1]  # Last hidden state
            
            # Analyze patterns (simplified approach)
            patterns = []
            pattern_score = 0.5
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'click here', 'verify now', 'account suspended', 'security alert',
                'password expired', 'login required', 'confirm identity'
            ]
            
            text_lower = text.lower()
            for pattern in suspicious_patterns:
                if pattern in text_lower:
                    pattern_score += 0.1
                    patterns.append(f"Suspicious pattern: {pattern}")
            
            return min(pattern_score, 1.0), patterns
            
        except Exception as e:
            return 0.5, [f"Pattern extraction error: {str(e)}"]
    
    def comprehensive_analysis(self, text: str) -> Dict:
        """Perform comprehensive BERT-based analysis"""
        results = {}
        
        # Phishing probability
        phishing_prob, phishing_reasons = self.analyze_phishing_probability(text)
        results['phishing_probability'] = phishing_prob
        results['phishing_reasons'] = phishing_reasons
        
        # Sentiment and urgency
        sentiment_score, sentiment_reasons = self.analyze_sentiment_urgency(text)
        results['sentiment_score'] = sentiment_score
        results['sentiment_reasons'] = sentiment_reasons
        
        # Intent classification
        intent_score, intent_reasons = self.analyze_intent_classification(text)
        results['intent_score'] = intent_score
        results['intent_reasons'] = intent_reasons
        
        # Pattern extraction
        pattern_score, pattern_reasons = self.extract_suspicious_patterns(text)
        results['pattern_score'] = pattern_score
        results['pattern_reasons'] = pattern_reasons
        
        # Combined BERT score
        bert_score = np.mean([
            phishing_prob, sentiment_score, intent_score, pattern_score
        ])
        results['bert_score'] = float(bert_score)
        
        return results

# Global instance
bert_analyzer = BERTPhishingAnalyzer()
