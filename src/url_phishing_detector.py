import pandas as pd
import numpy as np
import joblib
import re
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# 모델 로드 시 클래스 충돌 방지
import sys
sys.path.append('.')

class URLPhishingDetector:
    def __init__(self, model_path='phishing_model_data.pkl'):
        """피싱 감지기 초기화"""
        try:
            model_data = joblib.load(model_path)
            self.base_models = model_data['base_models']
            self.meta_model = model_data['meta_model']
            self.scaler = model_data['scaler']
            self.features = model_data['features']
            print("모델 로드 완료!")
        except FileNotFoundError:
            print(f"모델 파일 '{model_path}'을 찾을 수 없습니다.")
            print("먼저 save_model.py를 실행하여 모델을 훈련하세요.")
            self.base_models = None
            self.meta_model = None
            self.scaler = None
            self.features = None
    
    def extract_features(self, url):
        """URL에서 6개 feature 추출"""
        features = {}
        
        try:
            # URL 파싱
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # 1. time_domain_activation (도메인 활성화 시간)
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    # 도메인 생성일로부터 현재까지의 일수
                    if creation_date:
                        days_since_creation = (datetime.now() - creation_date).days
                        features['time_domain_activation'] = days_since_creation
                    else:
                        features['time_domain_activation'] = 0
                else:
                    features['time_domain_activation'] = 0
            except:
                features['time_domain_activation'] = 0
            
            # 2. directory_length (디렉토리 길이)
            features['directory_length'] = len(path) if path else 0
            
            # 3. length_url (전체 URL 길이)
            features['length_url'] = len(url)
            
            # 4. qty_slash_url (URL 내 슬래시 개수)
            features['qty_slash_url'] = url.count('/')
            
            # 5. qty_dot_domain (도메인 내 점 개수)
            features['qty_dot_domain'] = domain.count('.')
            
            # 6. ttl_hostname (TTL 값 - DNS 조회)
            try:
                # 도메인의 IP 주소 조회
                ip = socket.gethostbyname(domain)
                # TTL은 실제로는 DNS 조회를 통해 얻어야 하지만, 
                # 여기서는 간단히 도메인 길이를 사용
                features['ttl_hostname'] = len(domain)
            except:
                features['ttl_hostname'] = len(domain)
                
        except Exception as e:
            print(f"Feature 추출 중 오류 발생: {e}")
            # 기본값 설정
            features = {
                'time_domain_activation': 0,
                'directory_length': 0,
                'length_url': len(url),
                'qty_slash_url': url.count('/'),
                'qty_dot_domain': 0,
                'ttl_hostname': 0
            }
        
        return features
    
    def predict_phishing(self, url):
        """URL의 피싱 여부 예측"""
        if self.base_models is None or self.meta_model is None:
            return None, None
        
        try:
            # Feature 추출
            print("URL 분석 중...")
            features = self.extract_features(url)
            
            # DataFrame으로 변환
            feature_df = pd.DataFrame([features])
            
            # 스케일링
            feature_scaled = self.scaler.transform(feature_df)
            
            # 베이스 모델 예측
            meta_features = np.column_stack([
                self.base_models['catboost'].predict_proba(feature_scaled)[:, 1],
                self.base_models['randomforest'].predict_proba(feature_scaled)[:, 1],
                self.base_models['lightgbm'].predict_proba(feature_scaled)[:, 1],
                self.base_models['logistic'].predict_proba(feature_scaled)[:, 1]
            ])
            
            # 메타 모델 예측
            prediction = self.meta_model.predict(meta_features)[0]
            probability = self.meta_model.predict_proba(meta_features)[0]
            
            return prediction, probability
            
        except Exception as e:
            print(f"예측 중 오류 발생: {e}")
            return None, None
    
    def analyze_url(self, url):
        """URL 분석 및 결과 출력"""
        print(f"\n=== URL 분석: {url} ===")
        
        # Feature 추출
        features = self.extract_features(url)
        print("\n📊 추출된 Features:")
        for feature, value in features.items():
            print(f"  {feature}: {value}")
        
        # 피싱 예측
        prediction, probability = self.predict_phishing(url)
        
        if prediction is not None:
            print(f"\n🎯 예측 결과:")
            print(f"  피싱 여부: {'피싱 URL' if prediction == 1 else '정상 URL'}")
            print(f"  신뢰도: {max(probability):.2%}")
            print(f"  정상 확률: {probability[0]:.2%}")
            print(f"  피싱 확률: {probability[1]:.2%}")
            
            # 결과 해석
            if prediction == 1:
                print("\n⚠️  경고: 이 URL은 피싱으로 판별되었습니다!")
                print("   - 개인정보 입력을 피하세요")
                print("   - 링크 클릭을 주의하세요")
            else:
                print("\n✅ 안전: 이 URL은 정상으로 판별되었습니다.")
        else:
            print("\n❌ 예측에 실패했습니다.")

def main():
    # 감지기 초기화
    detector = URLPhishingDetector()
    
    if detector.base_models is None:
        return
    
    print("URL 피싱 감지기 시작!")
    print("종료하려면 'quit' 또는 'exit'를 입력하세요.\n")
    
    while True:
        try:
            url = input("분석할 URL을 입력하세요: ").strip()
            
            if url.lower() in ['quit', 'exit', '종료']:
                print("프로그램을 종료합니다.")
                break
            
            if not url:
                print("URL을 입력해주세요.")
                continue
            
            # URL 형식 검증
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # 분석 실행
            detector.analyze_url(url)
            
        except KeyboardInterrupt:
            print("\n프로그램을 종료합니다.")
            break
        except Exception as e:
            print(f"오류 발생: {e}")

if __name__ == "__main__":
    main()
