import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
# StandardScaler 제거 - 트리 기반 모델은 스케일링 불필요
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import lightgbm as lgb
import catboost as cb
import xgboost as xgb
from sklearn.model_selection import GridSearchCV
import warnings
warnings.filterwarnings('ignore')

class PhishingClassifier:
    def __init__(self):
        self.features = ['time_domain_activation', 'directory_length', 'length_url', 
                        'qty_slash_url', 'qty_dot_domain', 'ttl_hostname']
        self.base_models = {}
        self.meta_model = None
        # 스케일러 제거 - 트리 기반 모델은 스케일링 불필요
        
    def load_data(self, file_path):
        """데이터 로드 및 전처리"""
        print("데이터 로딩 중...")
        df = pd.read_csv(file_path)
        
        # 타겟 변수 설정
        target_col = 'phishing'
        print(f"타겟 변수: {target_col}")
        
        # 요청된 feature들만 선택
        available_features = [f for f in self.features if f in df.columns]
        missing_features = [f for f in self.features if f not in df.columns]
        
        if missing_features:
            print(f"누락된 features: {missing_features}")
            print(f"사용 가능한 features: {available_features}")
        
        X = df[available_features]
        y = df[target_col]
        
        print(f"데이터 형태: {X.shape}")
        print(f"클래스 분포:\n{y.value_counts()}")
        
        return X, y
    
    def train_base_models(self, X_train, y_train):
        """베이스 모델들 훈련"""
        print("\n베이스 모델 훈련 중...")
        
        # 1. CatBoost (디폴트 값 사용)
        print("CatBoost 훈련 중...")
        self.base_models['catboost'] = cb.CatBoostClassifier(verbose=False)
        self.base_models['catboost'].fit(X_train, y_train)
        
        # 2. Random Forest (디폴트 값 사용)
        print("Random Forest 훈련 중...")
        self.base_models['randomforest'] = RandomForestClassifier(random_state=42)
        self.base_models['randomforest'].fit(X_train, y_train)
        
        # 3. LightGBM (디폴트 값 사용)
        print("LightGBM 훈련 중...")
        self.base_models['lightgbm'] = lgb.LGBMClassifier(random_state=42)
        self.base_models['lightgbm'].fit(X_train, y_train)
        
        # 4. Logistic Regression (디폴트 값 사용)
        print("Logistic Regression 훈련 중...")
        self.base_models['logistic'] = LogisticRegression(random_state=42)
        self.base_models['logistic'].fit(X_train, y_train)
        
        print("베이스 모델 훈련 완료!")
    
    def create_meta_features(self, X):
        """메타 피처 생성"""
        meta_features = np.column_stack([
            self.base_models['catboost'].predict_proba(X)[:, 1],
            self.base_models['randomforest'].predict_proba(X)[:, 1],
            self.base_models['lightgbm'].predict_proba(X)[:, 1],
            self.base_models['logistic'].predict_proba(X)[:, 1]
        ])
        return meta_features
    
    def train_meta_model(self, X_train, y_train):
        """메타 모델 훈련 (XGBoost)"""
        print("\n메타 모델 훈련 중...")
        
        # 메타 피처 생성
        meta_features = self.create_meta_features(X_train)
        
        # XGBoost 메타 모델 훈련
        self.meta_model = xgb.XGBClassifier(
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
        
        self.meta_model.fit(meta_features, y_train)
        print("메타 모델 훈련 완료!")
    
    def predict(self, X):
        """예측 수행"""
        meta_features = self.create_meta_features(X)
        return self.meta_model.predict(meta_features)
    
    def predict_proba(self, X):
        """확률 예측"""
        meta_features = self.create_meta_features(X)
        return self.meta_model.predict_proba(meta_features)
    
    def evaluate_models(self, X_train, X_test, y_train, y_test):
        """모델 평가"""
        print("\n=== 개별 모델 성능 ===")
        
        for name, model in self.base_models.items():
            if hasattr(model, 'predict_proba'):
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                print(f"{name}: {accuracy:.4f}")
        
        print("\n=== Stacking 모델 성능 ===")
        y_pred_stacking = self.predict(X_test)
        accuracy_stacking = accuracy_score(y_test, y_pred_stacking)
        print(f"Stacking 모델 정확도: {accuracy_stacking:.4f}")
        
        print("\n=== 상세 분류 리포트 ===")
        print(classification_report(y_test, y_pred_stacking))
        
        return accuracy_stacking
    
    def train(self, X, y, test_size=0.3, random_state=42):
        """전체 훈련 프로세스"""
        # 데이터 분할
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # 스케일링 제거 - 트리 기반 모델은 스케일링 불필요
        
        # 베이스 모델 훈련
        self.train_base_models(X_train, y_train)
        
        # 메타 모델 훈련
        self.train_meta_model(X_train, y_train)
        
        # 모델 평가
        accuracy = self.evaluate_models(X_train, X_test, y_train, y_test)
        
        return accuracy

def main():
    # 분류기 초기화
    classifier = PhishingClassifier()
    
    # 데이터 로드
    X, y = classifier.load_data('dataset_full.csv')
    
    # 모델 훈련
    accuracy = classifier.train(X, y)
    
    print(f"\n최종 Stacking 모델 정확도: {accuracy:.4f}")
    
    # 모델 저장 (선택사항)
    import joblib
    joblib.dump(classifier, 'phishing_classifier_model.pkl')
    print("모델이 'phishing_classifier_model.pkl'로 저장되었습니다.")

if __name__ == "__main__":
    main()
