import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import lightgbm as lgb
import catboost as cb
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings('ignore')

def train_and_save_model():
    """모델 훈련 및 저장"""
    print("모델 훈련 및 저장 중...")
    
    # 데이터 로드
    df = pd.read_csv('../data/dataset_full.csv')
    
    # Feature 선택
    features = ['time_domain_activation', 'directory_length', 'length_url', 
                'qty_slash_url', 'qty_dot_domain', 'ttl_hostname']
    
    X = df[features]
    y = df['phishing']
    
    # 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # 스케일링 제거 - 트리 기반 모델은 스케일링 불필요
    
    # 베이스 모델들 정의
    base_models = [
        ('catboost', cb.CatBoostClassifier(verbose=0)),
        ('randomforest', RandomForestClassifier(random_state=42)),
        ('lightgbm', lgb.LGBMClassifier(random_state=42, verbose=0)),
        ('logistic', LogisticRegression(random_state=42))
    ]
    
    # XGBoost 메타 모델 정의
    meta_model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=4,
        min_child_weight=1,
        gamma=1.0733768183090244,
        learning_rate=0.8802067716505722,
        reg_lambda=15.350787907001227,
        reg_alpha=6.223308033832504,
        subsample=0.551810465659073,
        colsample_bytree=0.8587405278535516,
        random_state=42
    )
    
    # StackingClassifier 생성 및 훈련
    stacking_model = StackingClassifier(
        estimators=base_models,
        final_estimator=meta_model,
        cv=5,  # 5-fold cross validation
        stack_method='predict_proba',
        n_jobs=-1  # 모든 CPU 코어 사용
    )
    
    stacking_model.fit(X_train, y_train)
    
    # 모델 저장
    model_data = {
        'stacking_model': stacking_model,
        'features': features
    }
    
    joblib.dump(model_data, '../models/phishing_model_data.pkl')
    print("모델이 'phishing_model_data.pkl'로 저장되었습니다.")
    
    # 성능 평가
    y_pred = stacking_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"모델 정확도: {accuracy:.4f}")
    
    # 개별 모델 성능도 확인
    print("\n=== 개별 모델 성능 ===")
    for name, model in base_models:
        # verbose 설정 (이미 설정된 경우 무시)
        if hasattr(model, 'verbose'):
            model.verbose = 0
        model.fit(X_train, y_train)
        y_pred_individual = model.predict(X_test)
        acc_individual = accuracy_score(y_test, y_pred_individual)
        print(f"{name}: {acc_individual:.4f}")

if __name__ == "__main__":
    train_and_save_model()

