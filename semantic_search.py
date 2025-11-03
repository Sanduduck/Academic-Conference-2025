#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🍑 AI 의미 기반 검색 서버
KoSimCSE 모델을 사용한 한국어 임베딩 검색
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import json
import uvicorn
import os

app = FastAPI()

# 🍑 CORS 설정 - Express 서버와 통신 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🍑 데이터 및 모델 초기화
print("🍑 모델 로딩 중...")

# models.json 경로 - data 폴더와 public 폴더 둘 다 체크
MODEL_PATH = None
for path in ["data/models.json", "public/models.json"]:
    if os.path.exists(path):
        MODEL_PATH = path
        break

if not MODEL_PATH:
    print("⚠️ models.json 파일을 찾을 수 없습니다!")
    MODELS = []
else:
    with open(MODEL_PATH, "r", encoding="utf-8") as f:
        MODELS = json.load(f)
    print(f"🍑 {len(MODELS)}개 모델 로드 완료")

# 🍑 임베딩 모델 초기화 (한국어 특화 모델)
try:
    # 한국어 지원 모델들 시도
    model_name = "sentence-transformers/paraphrase-multilingual-mpnet-base-v2"  # 다국어 모델
    embed_model = SentenceTransformer(model_name)
    print(f"🍑 다국어 모델 로드 완료: {model_name}")
except Exception as e:
    print(f"⚠️ 모델 로딩 실패: {e}")
    # 기본 모델로 폴백
    embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    print("🍑 기본 영어 모델로 대체 로드")

# 🍑 문서 임베딩 생성 (title + description)
if MODELS:
    doc_texts = []
    for m in MODELS:
        title = m.get("title", "")
        description = m.get("description", "")
        # 과목 정보도 포함하면 더 정확한 검색 가능
        subject = m.get("subject", "")
        combined = f"{title} {description} {subject}"
        doc_texts.append(combined)

    print("🍑 문서 임베딩 생성 중...")
    doc_embeddings = embed_model.encode(doc_texts, show_progress_bar=True)

    # 🍑 FAISS 인덱스 생성 (코사인 유사도)
    dimension = doc_embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)  # Inner Product = Cosine similarity (정규화된 벡터)

    # L2 정규화로 코사인 유사도 계산 준비
    faiss.normalize_L2(doc_embeddings)
    index.add(doc_embeddings.astype('float32'))
    print(f"🍑 FAISS 인덱스 생성 완료 (차원: {dimension})")
else:
    index = None
    doc_embeddings = None

@app.get("/")
def root():
    """🍑 서버 상태 확인"""
    return {
        "status": "running",
        "message": "🍑 AI 의미 검색 서버 실행 중",
        "models_count": len(MODELS),
        "model_name": "paraphrase-multilingual-mpnet-base-v2"
    }

@app.get("/semantic_search")
def semantic_search(
    q: str = Query(..., description="검색 쿼리"),
    k: int = Query(20, description="반환할 결과 개수", ge=1, le=50)
):
    """
    🍑 의미 기반 검색 API

    Args:
        q: 검색어
        k: 반환할 결과 수 (최대 50)

    Returns:
        검색 결과 (id, title, description, score)
    """

    if not index or not MODELS:
        return {"error": "인덱스가 초기화되지 않았습니다", "results": []}

    # 🍑 쿼리 임베딩 생성
    query_embedding = embed_model.encode([q])
    faiss.normalize_L2(query_embedding)

    # 🍑 유사도 검색 수행
    k = min(k, len(MODELS))  # k가 전체 문서 수보다 크면 조정
    distances, indices = index.search(query_embedding.astype('float32'), k)

    # 🍑 결과 포맷팅
    results = []
    for score, idx in zip(distances[0], indices[0]):
        if idx < len(MODELS):  # 인덱스 범위 체크
            item = MODELS[idx]
            results.append({
                "id": item.get("id", idx),
                "title": item.get("title", ""),
                "description": item.get("description", ""),
                "subject": item.get("subject", ""),
                "score": float(score),  # 코사인 유사도 (0~1)
                "rank": len(results) + 1
            })

    return {
        "query": q,
        "count": len(results),
        "results": results,
        "method": "semantic_search",
        "model": "multilingual-mpnet"
    }

@app.get("/health")
def health_check():
    """🍑 헬스체크 엔드포인트"""
    return {"status": "healthy", "models_loaded": len(MODELS)}

if __name__ == "__main__":
    # 🍑 서버 실행 (포트 8000)
    print("🍑 AI 의미 검색 서버 시작: http://localhost:8000")
    print("🍑 API 문서: http://localhost:8000/docs")
    uvicorn.run("semantic_search:app", host="0.0.0.0", port=8000, reload=True)