#!/usr/bin/env node
/**
 * 🍑 AI 서버 시작 스크립트 (크로스 플랫폼)
 * Windows, Mac, Linux 모두 지원
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

console.log('🍑 AI 의미 검색 서버 시작 준비...');
console.log('=================================');

// Python 실행 파일 찾기 (Windows는 python, Unix는 python3 우선)
function getPythonCommand() {
  const commands = process.platform === 'win32'
    ? ['python', 'python3', 'py']
    : ['python3', 'python'];

  for (const cmd of commands) {
    try {
      const result = require('child_process').execSync(`${cmd} --version`, {
        stdio: 'pipe'
      });
      console.log(`✅ Python 찾음: ${cmd}`);
      return cmd;
    } catch (e) {
      continue;
    }
  }
  return null;
}

// 메인 실행
async function startAIServer() {
  const pythonCmd = getPythonCommand();

  if (!pythonCmd) {
    console.error('❌ Python이 설치되어 있지 않습니다!');
    console.error('');
    console.error('설치 방법:');
    console.error('  Windows: https://www.python.org/downloads/');
    console.error('  Mac: brew install python3');
    console.error('  Ubuntu: sudo apt install python3');
    process.exit(1);
  }

  // semantic_search.py 파일 확인
  const scriptPath = path.join(__dirname, 'semantic_search.py');
  if (!fs.existsSync(scriptPath)) {
    console.error('❌ semantic_search.py 파일을 찾을 수 없습니다!');
    process.exit(1);
  }

  console.log('🍑 필요한 패키지 설치 중...');
  console.log('  (첫 실행 시 몇 분 소요될 수 있습니다)');

  // pip install 실행
  const pipCmd = process.platform === 'win32' ? 'pip' : 'pip3';
  const pipInstall = spawn(pipCmd, ['install', '-r', 'requirements.txt'], {
    stdio: 'inherit',
    shell: true
  });

  pipInstall.on('error', () => {
    // pip3 실패시 pip 시도
    const pipInstall2 = spawn('pip', ['install', '-r', 'requirements.txt'], {
      stdio: 'inherit',
      shell: true
    });

    pipInstall2.on('close', (code) => {
      if (code === 0) {
        runServer(pythonCmd, scriptPath);
      } else {
        console.error('❌ 패키지 설치 실패');
        process.exit(1);
      }
    });
  });

  pipInstall.on('close', (code) => {
    if (code === 0) {
      runServer(pythonCmd, scriptPath);
    }
  });
}

function runServer(pythonCmd, scriptPath) {
  console.log('');
  console.log('🍑 AI 의미 검색 서버 시작...');
  console.log('=================================');
  console.log('  주소: http://localhost:8000');
  console.log('  API 문서: http://localhost:8000/docs');
  console.log('');
  console.log('종료: Ctrl+C');
  console.log('=================================');

  const server = spawn(pythonCmd, [scriptPath], {
    stdio: 'inherit'
  });

  server.on('error', (err) => {
    console.error('❌ 서버 시작 실패:', err.message);
    process.exit(1);
  });

  server.on('close', (code) => {
    console.log(`🍑 AI 서버 종료 (코드: ${code})`);
    process.exit(code);
  });

  // Ctrl+C 처리
  process.on('SIGINT', () => {
    console.log('\n🍑 서버 종료 중...');
    server.kill('SIGINT');
  });
}

// 실행
startAIServer();