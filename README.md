# URL 피싱 감지기

## 📋 프로젝트 개요
URL의 피싱 여부를 판별하는 머신러닝 기반 알고리즘입니다.

## 🏗️ 프로젝트 구조
```
phishingclf/
├── 📁 src/                    # 소스 코드
│   ├── save_model.py              # 모델 훈련 및 저장 (StackingClassifier)
│   ├── url_phishing_detector.py   # CLI 버전 피싱 감지기
│   └── phishing_detector_gui.py   # GUI 버전 피싱 감지기
│
├── 📁 data/                   # 데이터 파일
│   └── dataset_full.csv           # 훈련 데이터셋
│
├── 📁 models/                 # 훈련된 모델들
│   └── phishing_model_data.pkl   # 훈련된 Stacking 모델 파일
│
├── 📁 docs/                   # 문서
│   ├── README.md                  # 프로젝트 설명서
│   └── requirements.txt           # 필요한 라이브러리 목록
│
└── 📁 notebooks/              # Jupyter 노트북 (선택사항)
```

## 🎯 주요 기능
- **URL 분석**: 6개 피처를 추출하여 피싱 여부 판별
- **Stacking 앙상블**: CatBoost, Random Forest, LightGBM, Logistic Regression + XGBoost
- **GUI 인터페이스**: 사용자 친화적인 그래픽 인터페이스 (tkinter 기반)
- **실시간 분석**: 별도 스레드에서 분석 수행으로 UI 블로킹 방지
- **이중 인터페이스**: GUI와 CLI 두 가지 방식 지원

## 📊 사용된 피처
1. `time_domain_activation`: 도메인 활성화 시간
2. `directory_length`: 디렉토리 길이
3. `length_url`: 전체 URL 길이
4. `qty_slash_url`: URL 내 슬래시 개수
5. `qty_dot_domain`: 도메인 내 점 개수
6. `ttl_hostname`: TTL 값 (도메인 길이로 대체)

## 🏆 모델 성능
- **정확도**: 95.57% (StackingClassifier)
- **클래스 분포**: 정상 URL (58,000개), 피싱 URL (30,647개)
- **테스트 비율**: 30%
- **개별 모델 성능**:
  - CatBoost: 95.45%
  - Random Forest: 95.52%
  - LightGBM: 95.14%
  - Logistic Regression: 90.24%

## 🚀 사용 방법

### 1. 모델 훈련
```bash
cd src
python save_model.py
```

### 2. GUI 실행
```bash
cd src
python phishing_detector_gui.py
```

GUI가 실행되면 별도의 창이 열리고, 다음과 같은 기능을 사용할 수 있습니다:
- **URL 입력**: 분석할 URL을 텍스트 필드에 입력
- **분석 버튼**: 입력된 URL의 피싱 여부를 분석
- **Clear 버튼**: URL 입력 필드를 초기화
- **결과 확인**: 피싱 확률과 상세 분석 결과를 실시간으로 확인

### 3. CLI 실행
```bash
cd src
python url_phishing_detector.py
```

CLI 버전은 명령줄에서 직접 URL을 입력하여 분석할 수 있습니다.

## 📦 필요한 라이브러리
- pandas >= 1.3.0
- numpy >= 1.21.0
- scikit-learn >= 1.0.0
- xgboost >= 1.5.0
- lightgbm >= 3.3.0
- catboost >= 1.0.0
- python-whois >= 0.9.0
- joblib >= 1.1.0

## 🔧 설치 방법
```bash
pip install -r docs/requirements.txt
```

## 📝 라이선스
이 프로젝트는 교육 및 연구 목적으로 제작되었습니다.

