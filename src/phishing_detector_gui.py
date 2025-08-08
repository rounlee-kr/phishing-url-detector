import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import pandas as pd
import numpy as np
import joblib
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import threading
import warnings
warnings.filterwarnings('ignore')

class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("URL 피싱 감지기")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # 모델 로드
        self.load_model()
        
        # GUI 구성
        self.create_widgets()
        
    def load_model(self):
        """모델 로드"""
        try:
            # 실행 파일 내부의 모델 파일 경로 찾기
            import sys
            import os
            
            if getattr(sys, 'frozen', False):
                # PyInstaller로 생성된 실행 파일인 경우
                application_path = sys._MEIPASS
            else:
                # 일반 Python 스크립트인 경우
                application_path = os.path.dirname(os.path.abspath(__file__))
            
            model_path = os.path.join(application_path, '..', 'models', 'phishing_model_data.pkl')
            model_data = joblib.load(model_path)
            
            self.stacking_model = model_data['stacking_model']
            self.features = model_data['features']
            self.model_loaded = True
        except FileNotFoundError:
            messagebox.showerror("오류", "모델 파일을 찾을 수 없습니다.\n먼저 save_model.py를 실행하여 모델을 훈련하세요.")
            self.model_loaded = False
        except Exception as e:
            messagebox.showerror("오류", f"모델 로드 중 오류 발생: {e}")
            self.model_loaded = False
    
    def create_widgets(self):
        """GUI 위젯 생성"""
        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 제목
        title_label = ttk.Label(main_frame, text="🔍 URL 피싱 감지기", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # URL 입력 프레임
        input_frame = ttk.LabelFrame(main_frame, text="URL 입력", padding="10")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # URL 입력 필드
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(input_frame, textvariable=self.url_var, width=60, font=('Arial', 10))
        url_entry.grid(row=0, column=0, padx=(0, 10))
        url_entry.focus()
        
        # 버튼 프레임
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=0, column=1)
        
        # 분석 버튼
        analyze_btn = ttk.Button(button_frame, text="분석", command=self.analyze_url_thread)
        analyze_btn.grid(row=0, column=0, padx=(0, 5))
        
        # Clear 버튼
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_url)
        clear_btn.grid(row=0, column=1)
        
        # 결과 프레임
        result_frame = ttk.LabelFrame(main_frame, text="분석 결과", padding="10")
        result_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # 결과 표시 영역
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=80, 
                                                   font=('Consolas', 9))
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 상태 표시줄
        self.status_var = tk.StringVar()
        self.status_var.set("준비됨")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                font=('Arial', 9))
        status_label.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        # 그리드 가중치 설정
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        # Enter 키 바인딩
        url_entry.bind('<Return>', lambda e: self.analyze_url_thread())
        
        # 창 닫기 이벤트 바인딩
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def clear_url(self):
        """URL 입력 필드 지우기"""
        self.url_var.set("")
        # URL 입력 필드에 포커스 설정
        self.root.focus_force()
    
    def on_closing(self):
        """창 닫기 이벤트"""
        self.root.quit()
        self.root.destroy()
    
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
                ip = socket.gethostbyname(domain)
                features['ttl_hostname'] = len(domain)
            except:
                features['ttl_hostname'] = len(domain)
                
        except Exception as e:
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
        if not self.model_loaded:
            return None, None
        
        try:
            # Feature 추출
            features = self.extract_features(url)
            
            # DataFrame으로 변환
            feature_df = pd.DataFrame([features])
            
            # Stacking 모델 예측
            prediction = self.stacking_model.predict(feature_df)[0]
            probability = self.stacking_model.predict_proba(feature_df)[0]
            
            return prediction, probability, features
            
        except Exception as e:
            return None, None, None
    
    def analyze_url_thread(self):
        """별도 스레드에서 URL 분석"""
        if not self.model_loaded:
            messagebox.showerror("오류", "모델이 로드되지 않았습니다.")
            return
        
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("경고", "URL을 입력해주세요.")
            return
        
        # URL 형식 검증
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # 분석 시작
        self.status_var.set("분석 중...")
        self.root.update()
        
        # 별도 스레드에서 분석 실행
        thread = threading.Thread(target=self.analyze_url, args=(url,))
        thread.daemon = True
        thread.start()
    
    def analyze_url(self, url):
        """URL 분석 및 결과 표시"""
        try:
            # 피싱 예측
            prediction, probability, features = self.predict_phishing(url)
            
            # 결과 텍스트 초기화
            self.result_text.delete(1.0, tk.END)
            
            if prediction is not None:
                # 결과 표시
                result = f"=== URL 분석 결과 ===\n"
                result += f"분석 URL: {url}\n\n"
                
                result += "📊 추출된 Features:\n"
                for feature, value in features.items():
                    result += f"  {feature}: {value}\n"
                
                result += f"\n🎯 예측 결과:\n"
                result += f"  피싱 여부: {'피싱 URL' if prediction == 1 else '정상 URL'}\n"
                result += f"  신뢰도: {max(probability):.2%}\n"
                result += f"  정상 확률: {probability[0]:.2%}\n"
                result += f"  피싱 확률: {probability[1]:.2%}\n"
                
                if prediction == 1:
                    result += "\n⚠️  경고: 이 URL은 피싱으로 판별되었습니다!\n"
                    result += "   - 개인정보 입력을 피하세요\n"
                    result += "   - 링크 클릭을 주의하세요\n"
                else:
                    result += "\n✅ 안전: 이 URL은 정상으로 판별되었습니다.\n"
                
                self.result_text.insert(tk.END, result)
                
                # 상태 업데이트
                self.status_var.set("분석 완료")
                
            else:
                self.result_text.insert(tk.END, "❌ 예측에 실패했습니다.")
                self.status_var.set("분석 실패")
                
        except Exception as e:
            self.result_text.insert(tk.END, f"오류 발생: {e}")
            self.status_var.set("오류 발생")

def main():
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
