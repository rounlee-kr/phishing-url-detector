# 데이터셋 정보

## 📊 dataset_full.csv

### 📋 데이터셋 개요
URL 피싱 감지를 위한 머신러닝 모델 훈련에 사용된 데이터셋입니다.

### 🔗 출처
이 데이터셋은 [GregaVrbancic의 Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)에서 가져온 것입니다.

**원본 저장소**: https://github.com/GregaVrbancic/Phishing-Dataset

**웹 애플리케이션**: https://gregavrbancic.github.io/Phishing-Dataset/

### 📈 데이터 구성
- **총 샘플 수**: 88,647개
- **정상 URL**: 58,000개 (labeled as 0)
- **피싱 URL**: 30,647개 (labeled as 1)
- **원본 피처 수**: 111개
- **사용된 피처 수**: 6개 (선택된 피처만 사용)

### 🎯 사용된 피처
1. `time_domain_activation`: 도메인 활성화 시간
2. `directory_length`: 디렉토리 길이
3. `length_url`: 전체 URL 길이
4. `qty_slash_url`: URL 내 슬래시 개수
5. `qty_dot_domain`: 도메인 내 점 개수
6. `ttl_hostname`: TTL 값 (도메인 길이로 대체)

### ⚠️ 주의사항
- 이 데이터셋은 교육 및 연구 목적으로만 사용됩니다.
- 실제 운영 환경에서 사용하기 전에 추가적인 검증이 필요합니다.
- 데이터셋의 정확성과 최신성을 보장할 수 없습니다.

### 📝 라이선스
원본 데이터셋의 라이선스에 따라 사용됩니다. 상업적 사용을 원하는 경우 별도의 라이선스 확인이 필요할 수 있습니다.

### 📚 인용
이 데이터셋을 사용할 때는 다음 논문을 인용해주세요:

```
G. Vrbančič, I. Jr. Fister, V. Podgorelec. Datasets for Phishing Websites Detection. 
Data in Brief, Vol. 33, 2020, DOI: 10.1016/j.dib.2020.106438
```

### 🔄 데이터 업데이트
더 정확하고 최신의 데이터셋을 사용하려면:
1. PhishTank API를 통한 실시간 데이터 수집
2. 정기적인 데이터셋 업데이트
3. 다양한 출처의 데이터 통합

### 📞 문의
데이터셋 출처에 대한 정확한 정보가 필요하시면 프로젝트 이슈를 통해 문의해주세요.
