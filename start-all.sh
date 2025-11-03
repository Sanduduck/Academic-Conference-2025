#!/bin/bash
# 🍑 전체 서버 시작 스크립트 (Express + AI)

echo "🍑 전체 서버 시작 스크립트"
echo "================================="

# 터미널 색상 설정
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# npm 패키지 설치
echo -e "${YELLOW}🍑 Express 서버 패키지 설치 중...${NC}"
npm install

# Python AI 서버를 백그라운드로 실행
echo -e "${YELLOW}🍑 AI 의미 검색 서버 시작 중...${NC}"

# Python 가상환경 체크 및 생성
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# 가상환경 활성화 및 AI 서버 백그라운드 실행
(
    source venv/bin/activate
    pip install -q -r requirements.txt
    python semantic_search.py &
) 2>/dev/null

AI_PID=$!
echo -e "${GREEN}✅ AI 서버 시작됨 (PID: $AI_PID)${NC}"

# 1초 대기
sleep 1

# Express 서버 실행
echo -e "${YELLOW}🍑 Express 서버 시작 중...${NC}"
echo ""
echo "================================="
echo -e "${GREEN}🍑 서버 정보:${NC}"
echo "   Express 서버: http://localhost:3000"
echo "   AI 검색 서버: http://localhost:8000"
echo "   AI API 문서: http://localhost:8000/docs"
echo ""
echo "종료하려면 Ctrl+C를 누르세요."
echo "================================="

# Express 서버 실행
npm start

# Express 서버 종료 시 AI 서버도 종료
echo -e "${YELLOW}🍑 서버 종료 중...${NC}"
kill $AI_PID 2>/dev/null
echo -e "${GREEN}✅ 모든 서버가 종료되었습니다.${NC}"