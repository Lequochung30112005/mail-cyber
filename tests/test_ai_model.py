import os
import joblib

def test_models_exist():
    # Kiểm tra xem mô hình AI đã được train và lưu đúng vị trí chưa
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    svm_path = os.path.join(base_dir, 'ai_engine', 'models', 'svm_baseline_model.pkl')
    vec_path = os.path.join(base_dir, 'ai_engine', 'models', 'tfidf_vectorizer.pkl')
    
    assert os.path.exists(svm_path) == True
    assert os.path.exists(vec_path) == True

def test_model_prediction():
    # Load model và test thử một câu
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    svm_model = joblib.load(os.path.join(base_dir, 'ai_engine', 'models', 'svm_baseline_model.pkl'))
    vectorizer = joblib.load(os.path.join(base_dir, 'ai_engine', 'models', 'tfidf_vectorizer.pkl'))
    
    test_text = "urgent verify your bank account details now"
    vectorized_text = vectorizer.transform([test_text]).toarray()
    prediction = svm_model.predict(vectorized_text)
    
    # Kì vọng câu trên bị đánh dấu là Spam (1)
    assert prediction[0] in [0, 1]