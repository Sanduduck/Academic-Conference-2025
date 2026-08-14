# **3D 교육 학습 플랫폼 — 웹 + AI 하이브리드 검색**

### 📄 학술대회 발표 연구의 웹·AI 플랫폼 파트 (팀 코드톡톡)

> 중·고등 3D 교육 콘텐츠를, **문자열 검색과 AI 의미 검색을 결합한 하이브리드 검색**으로 탐색하는 웹 학습 플랫폼.
> 정확한 교과 용어를 몰라도 *"세포에서 에너지를 만드는 구조"* 같은 문장으로 관련 자료를 찾습니다.

![HTML](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=flat&logo=express&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)
![Paper](https://img.shields.io/badge/Published-Conference%20Paper-B31B1B?style=flat)

🔗 **저장소** : https://github.com/Sanduduck/Academic-Conference-2025

---

## 📄 학술 발표 정보

> **「VR 기기를 이용한 중고등학생 3D 교육 도움 시스템」**
> *3D Education Assistance System for Middle and High School Students Using VR Devices*
>
> **학회** — 2025년 한국실천공학교육학회 학술발표대회 논문집 (Vol.1, No.1)
> **저자** — 이승헌, 김은수, 김재광, 김준영, 오유진, **박동진**, 문형진(지도) · 성결대학교 정보통신공학부

정식 심사를 거쳐 학회 논문집에 게재된 공동 연구입니다. 논문은 Oculus Quest 2 + Unity 기반 VR 3D 교육 시스템을 제안하며, 그 안에서 **학습자가 콘텐츠에 접근하는 웹 학습 플랫폼**을 담당·구현한 것이 이 저장소입니다.

---

## 📌 프로젝트 소개

* 과목·단원별 3D 교육 콘텐츠를 탐색·학습하는 **웹 포털**입니다.
* 핵심은 **하이브리드 검색** — 학생이 정확한 교과 용어("미토콘드리아")를 몰라도, 문장형 검색("세포에서 에너지를 만드는 구조")으로 관련 개념을 찾도록 문자열 검색과 AI 의미 검색을 결합했습니다.
* Node.js 웹 서버와 Python AI 서버를 분리해, **AI 서버가 없어도 기본 검색은 그대로 동작**하도록 설계했습니다.

---

## 🔗 프로젝트 여정 — 이 플랫폼이 남긴 것

이 저장소(2025)는 팀의 VR 3D 교육 연구에서 **웹·AI 파트**를 맡아 구현한 결과물입니다. 여기서 만든 두 가지가 이후 프로젝트의 뼈대가 되었습니다.

1. **하이브리드 검색 엔진** — 문자열 + AI 의미 검색을 가중 병합하는 구조
2. **웹 서버 / AI 서버 분리 아키텍처** — AI 장애 시에도 기본 기능 유지

이 구조가 그대로 발전해, 2026년 ICT 경진대회 출품작인 웹 기반 **[3D Learning Atlas](https://github.com/Sanduduck/ICT-Innovation-Project-Competition)** 의 하이브리드 검색 + AI 노트 시스템이 되었습니다.

> **VR 연구(2025) → 웹·AI 플랫폼 구현(이 저장소) → 3D Learning Atlas(2026)** 로 이어진 연속된 흐름의 중간 단계입니다.

---

## 👤 담당 (박동진)

이 연구에서 **웹 학습 플랫폼과 AI 하이브리드 검색**을 담당했습니다.
* 문자열 + KoSimCSE 의미 검색을 가중 병합하는 **하이브리드 검색 엔진** 설계·구현
* Node.js 웹 서버 ↔ Python AI 서버 **분리 아키텍처** 및 장애 대비(graceful degradation)

*(공동저자 6인 연구이며, 위는 본 저장소에 해당하는 담당 범위입니다.)*

---

## 🛠️ 사용 기술

**Frontend** — HTML / CSS / JavaScript
**Backend** — Node.js + Express (`:3000`)
**AI 서버** — Python + FastAPI (`:8000`)
* **의미 검색** — KoSimCSE-roberta (한국어 특화 임베딩)
**Database** — SQLite3

---

## 🎯 주요 기능

| 기능 | 설명 |
| --- | --- |
| **하이브리드 검색** | 문자열 매칭(정확) + AI 의미 검색(개념 확장)을 가중 병합 |
| **3D 콘텐츠 탐색** | 과목·단원별 3D 교육 모델 목록 탐색 |
| **의미 기반 추천** | "에너지" 검색 시 "광합성·ATP·미토콘드리아" 등 관련 개념까지 |
| **AI 독립 동작** | AI 서버 없이도 문자열 검색은 정상 작동 |

---

## 🧠 기술적 의사결정 (Technical Decisions)

<details>
<summary><b>1. 검색 — 왜 문자열과 AI를 65:35로 섞었는가</b></summary>

<br>

**문제**
문자열 검색만 쓰면 학습자가 **정확한 교과 용어를 알아야만** 자료를 찾습니다. 반대로 AI 의미 검색만 쓰면 정확한 키워드 일치가 흐려지고, 엉뚱하게 관련도 낮은 결과가 섞이기도 합니다.

**선택 — 가중 평균 병합**
두 방식을 함께 돌리고 결과를 가중 병합했습니다. **문자열 65% : AI 35% (`alpha = 0.65`)** 로, 정확도를 보장하는 문자열 검색을 주력으로 두고 AI 의미 검색으로 개념을 확장·보완하는 비중으로 잡았습니다.

```
[검색어 "에너지"]
   ├─ 문자열 검색 → "에너지" 포함 항목
   └─ AI 의미 검색 → "광합성·ATP·미토콘드리아" 등 관련 개념
        ↓ 가중 병합 (65 : 35)
   [최종 정렬 결과]
```

**튜닝 가능하게 설계**
`alpha` 값을 바꿔 검색 성향을 조절할 수 있게 했습니다 — 0.8이면 더 정확(키워드 중심), 0.5면 더 포괄(개념 중심).

**결과 / 트레이드오프**
"정확 일치"와 "개념 확장"의 장점을 한 번에 얻되, 그 균형점을 하나의 파라미터로 조정 가능하게 만들었습니다. 65:35는 교육 콘텐츠 특성(정확한 단원 매칭이 우선)을 고려한 기본값입니다.

</details>

<details>
<summary><b>2. 임베딩 모델 — 왜 KoSimCSE인가</b></summary>

<br>

**문제**
검색 대상이 **한국어 교과 개념**인데, 영어 범용 임베딩 모델은 한국어 문장의 의미 유사도를 정확히 잡지 못합니다.

**선택**
한국어 문장 임베딩에 특화된 **KoSimCSE-roberta**를 채택해, "세포에서 에너지를 만드는 구조" 같은 한국어 문장 검색의 의미 매칭 정확도를 확보했습니다.

**결과 / 트레이드오프**
현재 29개 모델 규모에서 첫 검색은 모델 로딩으로 3~5초, 이후 검색은 **~200ms**로 처리됩니다.

</details>

<details>
<summary><b>3. 서버 분리 — AI가 죽어도 검색은 살아있게</b></summary>

<br>

**문제**
AI 의미 검색은 무거운 Python 서버가 필요한데, 이 서버가 안 떠 있거나 죽으면 **검색 기능 전체가 멈출** 위험이 있었습니다.

**선택**
Node.js 웹 서버(`:3000`)와 Python AI 서버(`:8000`)를 **분리**하고, AI 서버가 없으면 **자동으로 문자열 검색만으로 동작**하도록 설계했습니다("AI 서버 실행 중이지 않습니다" 안내와 함께 기본 검색 유지).

**결과 / 트레이드오프**
AI라는 무거운 의존성을 **선택적 강화 기능**으로 격리해, 핵심인 검색이 항상 살아있도록 안정성을 확보했습니다. 이 graceful degradation 설계는 이후 3D Learning Atlas의 다단계 폴백 구조로 발전했습니다.

</details>

<details>
<summary><b>4. 확장 전략 — 지금은 왜 단순하게 두는가</b></summary>

<br>

**판단**
현재 데이터는 29개 모델 규모라, 무거운 전문 검색엔진 없이 인메모리 연산만으로 모든 검색이 200ms 이내에 처리됩니다. 오버엔지니어링을 피하고, 규모에 따른 단계적 확장 경로만 미리 정의해 두었습니다.

| 규모 | 전략 |
| --- | --- |
| ~100개 | 현재 구조 유지 |
| ~500개 | 서버 사이드 검색 도입 |
| 1000개+ | Elasticsearch 등 전문 검색엔진 |

**결과**
"지금 필요한 만큼만" 구현하되 성장 경로를 의식한 설계로, MVP 단계의 단순함과 향후 확장성을 모두 확보했습니다.

</details>

---

## 🧩 시스템 구조

```
┌──────────────────────────────────────────────┐
│            클라이언트 (브라우저)                 │
│           HTML / CSS / JavaScript             │
└───────────────────────┬──────────────────────┘
                        │ HTTP
┌───────────────────────▼──────────────────────┐
│           Node.js Express (:3000)             │
│   콘텐츠 API · 검색 프록시 · SQLite            │
└───────────────────────┬──────────────────────┘
                        │ 의미 검색 요청 (선택적)
┌───────────────────────▼──────────────────────┐
│          Python FastAPI AI 서버 (:8000)        │
│   KoSimCSE 임베딩 · 의미 유사도 계산           │
└──────────────────────────────────────────────┘

── AI 서버가 없으면 → 문자열 검색만으로 자동 동작
```

---

## 🚀 설치 및 실행

```bash
git clone https://github.com/Sanduduck/Academic-Conference-2025.git
cd Academic-Conference-2025

# 방법 1: 전체 한 번에 (권장)
npm run install:all      # 첫 실행 시 패키지 설치
npm run start:all        # Express + AI 서버 동시 실행

# 방법 2: 개별 실행
npm install && npm start # Express만 (:3000, AI 검색 없이도 동작)
npm run ai:install       # (첫 실행) AI 서버 패키지
npm run ai               # AI 서버 (:8000)
```

**요구사항** — Node.js 14+, Python 3.8+ (설치 시 "Add Python to PATH" 체크)

**검색 가중치 조정** — `public/index.html`의 `const alpha = 0.65;` 값 변경 (0.8 정확 / 0.5 포괄)
