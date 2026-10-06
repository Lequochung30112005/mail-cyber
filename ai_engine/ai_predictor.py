import os
import sys
import logging
import re
import numpy as np
import joblib
from pathlib import Path
from urllib.parse import urlparse

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

logger = logging.getLogger(__name__)

# ============================================================
# MODEL PATH
# ============================================================

DOCKER_MODELS_DIR = Path("/app/ai_engine/models")
LOCAL_MODELS_DIR = Path(__file__).parent / "models"

MODELS_DIR = (
    DOCKER_MODELS_DIR
    if DOCKER_MODELS_DIR.exists()
    else LOCAL_MODELS_DIR
)

logger.info(f"📁 Models directory: {MODELS_DIR}")

# ============================================================
# SINGLETON
# ============================================================

_instance = None


# ============================================================
# LOAD PKL
# ============================================================

def load_pkl(path):
    if not path.exists():
        logger.warning(f"⚠️ Không tìm thấy file pkl: {path.name}")
        return None

    try:
        model = joblib.load(path)
        logger.info(f"✅ Loaded PKL: {path.name}")
        return model
    except Exception as e:
        logger.error(f"❌ Lỗi load {path.name}: {e}")
        return None


# ============================================================
# LOAD H5
# ============================================================

def load_h5(path):
    if not path.exists():
        logger.warning(f"⚠️ Không tìm thấy file h5: {path.name}")
        return None

    try:
        import tensorflow as tf
        # Thêm compile=False để tránh lỗi load các custom optimizer như AdamW
        model = tf.keras.models.load_model(path, compile=False)

        logger.info(f"✅ Loaded H5: {path.name}")

        try:
            logger.info(f"🧠 BiLSTM input shape: {model.input_shape}")
            logger.info(f"🧠 BiLSTM output shape: {model.output_shape}")
        except Exception:
            pass

        return model

    except Exception as e:
        logger.error(f"❌ Lỗi load H5 {path.name}: {e}")
        return None


# ============================================================
# CYBERMAIL PREDICTOR
# ============================================================

class CyberMailPredictor:

    def __init__(self):
        logger.info("🤖 Khởi tạo CyberMailPredictor")
        logger.info("🔐 Kiến trúc: HHO-SVM = Spam | BiLSTM + URL = Phishing")

        # 1. BiLSTM + TOKENIZER
        self.bilstm_model = load_h5(MODELS_DIR / "bilstm_adamw_model.h5")
        self.tokenizer = load_pkl(MODELS_DIR / "tokenizer.pkl")

        # 2. HHO-SVM
        self.hho_model = load_pkl(MODELS_DIR / "model_hho_final.pkl")
        self.pipeline_config = load_pkl(MODELS_DIR / "pipeline_config.pkl")

        # 3. URL PHISHING MODEL
        self.url_model = load_pkl(MODELS_DIR / "url_phishing_model.pkl")

        # 4. KEYWORDS
        self.spam_keywords = [
            "free", "win", "click here", "discount", "offer",
            "limited", "khuyến mãi", "trúng thưởng"
        ]

        self.phishing_keywords = [
            "urgent", "compromised", "verify", "password",
            "suspended", "account", "mật khẩu", "khẩn cấp", "urgren"
        ]

        self.MAX_SPAM_KEYWORD_BONUS = 0.05
        self.MAX_PHISHING_KEYWORD_BONUS = 0.05

        logger.info("🔑 Spam keyword bonus MAX: 5%")
        logger.info("🔑 Phishing keyword bonus MAX: 5%")

    def _empty(self):
        return {
            'spam_percent': 0.0,
            'phishing_percent': 0.0,
            'risk_level': 'safe',
            'top_keywords': [],
            'details': {
                'bilstm_score': 0.0,
                'hho_score': 0.0,
                'url_score': 0.0,
                'spam_hybrid': 0.0,
                'phishing_hybrid': 0.0,
                'spam_keyword_bonus': 0.0,
                'phishing_keyword_bonus': 0.0
            }
        }

    def _extract_tabular_features(self, text: str, num_features=3000):
        features = np.zeros(num_features)
        features[0] = len(text)
        features[1] = text.count(' ')
        features[2] = len([c for c in text if c.isupper()])
        features[3] = text.count('!')
        features[4] = text.count('$')
        return features.reshape(1, -1)

    def _get_url_phishing_score(self, urls: list):
        if not urls:
            return 0.0

        if not self.url_model:
            return 0.0

        scores = []
        for url in urls:
            try:
                if hasattr(self.url_model, "predict_proba"):
                    pred_prob = self.url_model.predict_proba([url])
                    score = float(pred_prob[0][1]) if len(pred_prob[0]) > 1 else float(pred_prob[0][0])
                elif hasattr(self.url_model, "predict"):
                    pred = self.url_model.predict([url])
                    score = float(pred[0])
                else:
                    score = 0.0

                score = max(0.0, min(score, 1.0))
                scores.append(score)
            except Exception as e:
                logger.error(f"❌ Lỗi phân tích URL '{url}': {e}")

        return max(scores) if scores else 0.0

    def predict(self, email_text: str, subject: str = "", urls: list = None):
        if not email_text or not email_text.strip():
            return self._empty()

        if urls is None:
            urls = []

        full_text = f"{subject} {email_text}".strip()

        logger.info("")
        logger.info("=" * 80)
        logger.info("📧 BẮT ĐẦU PHÂN TÍCH EMAIL")
        logger.info("=" * 80)

        bilstm_score = 0.0
        hho_score = 0.0
        url_score = 0.0

        # 1. BiLSTM PHISHING MODEL
        logger.info("🧠 [1/4] BiLSTM PHISHING ANALYSIS")
        if self.bilstm_model and self.tokenizer:
            try:
                from tensorflow.keras.preprocessing.sequence import pad_sequences
                sequences = self.tokenizer.texts_to_sequences([full_text])
                padded = pad_sequences(sequences, maxlen=200, padding='post', truncating='post')

                pred = self.bilstm_model.predict(padded, verbose=0)
                logger.info(f"🧠 RAW BiLSTM OUTPUT: {pred}")

                if pred is not None and len(pred) > 0:
                    bilstm_score = float(np.squeeze(pred).flat[0])

                bilstm_score = max(0.0, min(bilstm_score, 1.0))
                logger.info(f"🧠 BiLSTM phishing score: {bilstm_score:.4f}")
            except Exception as e:
                logger.exception(f"❌ Lỗi BiLSTM predict: {e}")
        else:
            logger.warning("⚠️ BiLSTM model hoặc tokenizer không được load")

        # 2. HHO-SVM SPAM MODEL
        logger.info("🧮 [2/4] HHO-SVM SPAM ANALYSIS")
        if self.hho_model:
            try:
                raw_feat = self._extract_tabular_features(full_text)
                if self.pipeline_config and 'scaler' in self.pipeline_config:
                    scaler = self.pipeline_config['scaler']
                    target_size = scaler.mean_.shape[0]

                    if raw_feat.shape[1] < target_size:
                        padded_feat = np.zeros((1, target_size))
                        padded_feat[0, :raw_feat.shape[1]] = raw_feat
                        raw_feat = padded_feat
                    elif raw_feat.shape[1] > target_size:
                        raw_feat = raw_feat[:, :target_size]

                    scaled_feat = scaler.transform(raw_feat)
                    indices = self.pipeline_config.get('indices', [])
                    selected_feat = scaled_feat[:, indices] if len(indices) > 0 else scaled_feat

                    if hasattr(self.hho_model, "predict_proba"):
                        hho_score = float(self.hho_model.predict_proba(selected_feat)[0][1])
                    else:
                        decision = self.hho_model.decision_function(selected_feat)
                        val = decision[0] if hasattr(decision, "__getitem__") else decision
                        hho_score = float(1 / (1 + np.exp(-val)))

                    hho_score = max(0.0, min(hho_score, 1.0))
                    logger.info(f"🧮 HHO-SVM spam score: {hho_score:.4f}")
            except Exception as e:
                logger.exception(f"❌ Lỗi HHO predict: {e}")

        # 3. URL PHISHING MODEL
        url_score = self._get_url_phishing_score(urls)

        # 4. KEYWORD ANALYSIS
        text_lower = full_text.lower()
        spam_hits = [kw for kw in self.spam_keywords if kw in text_lower]
        phish_hits = [kw for kw in self.phishing_keywords if kw in text_lower]

        raw_spam_score = hho_score
        raw_phishing_score = (0.7 * bilstm_score) + (0.3 * url_score)

        spam_bonus = min(len(spam_hits) * 0.01, self.MAX_SPAM_KEYWORD_BONUS)
        phish_bonus = min(len(phish_hits) * 0.01, self.MAX_PHISHING_KEYWORD_BONUS)

        final_spam_score = min(raw_spam_score + spam_bonus, 1.0)
        final_phish_score = min(raw_phishing_score + phish_bonus, 1.0)

        combined_keywords = list(dict.fromkeys(spam_hits + phish_hits))
        top_keywords = combined_keywords[:5]

        total_score_percent = ((final_spam_score * 100) * 0.5) + ((final_phish_score * 100) * 0.5)
        has_no_subject = not subject or not subject.strip()

        if total_score_percent >= 45.0 or url_score > 0.5 or final_phish_score >= 0.5:
            risk = "dangerous"
        elif total_score_percent >= 15.0 or final_spam_score >= 0.25 or final_phish_score >= 0.25 or has_no_subject:
            risk = "suspicious"
        else:
            risk = "safe"

        result = {
            'spam_percent': round(final_spam_score * 100, 1),
            'phishing_percent': round(final_phish_score * 100, 1),
            'risk_level': risk,
            'top_keywords': top_keywords,
            'details': {
                'bilstm_score': round(bilstm_score, 4),
                'hho_score': round(hho_score, 4),
                'url_score': round(url_score, 4),
                'spam_hybrid': round(final_spam_score, 4),
                'phishing_hybrid': round(final_phish_score, 4),
                'spam_keyword_bonus': round(spam_bonus, 4),
                'phishing_keyword_bonus': round(phish_bonus, 4)
            }
        }

        logger.info(f"✅ HOÀN TẤT PHÂN TÍCH EMAIL | Risk: {result['risk_level']}")
        return result


def get_predictor():
    global _instance
    if _instance is None:
        _instance = CyberMailPredictor()
    return _instance
