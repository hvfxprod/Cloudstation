<div align="center">
</div>

# CloudStation Pro

로컬 및 Docker 환경에서 실행할 수 있는 웹 기반 파일/시스템 관리 인터페이스입니다.

## 로컬 실행

**필요:** Node.js

1. 의존성 설치: `npm install`
2. (선택) [.env.local](.env.local)에 API 키 설정 시 앱 내 어시스턴트 기능 사용 가능
3. 실행: `npm run dev`

## Docker 배포 (서버 + SMB 공유 연동)

**필요:** Docker, Docker Compose

1. 프로젝트 루트에서 빌드 및 실행:
   ```bash
   docker compose up -d --build
   ```
2. 호스트의 `/mnt/Theh_1/SMB_Share` 경로가 컨테이너 내부 `/data`로 마운트됩니다.  
   File Station의 **My Drive**가 이 경로의 파일/폴더를 표시합니다.
3. 접속: **http://서버IP:9999** (포트 9999)

환경 변수(선택):
- `DATA_PATH`: 컨테이너 내부 데이터 경로 (기본값: `/data`)
- `PORT`: 서버 포트 (기본값: `9999`)

다른 호스트 경로를 쓰려면 `docker-compose.yml`의 `volumes`를 수정하세요.
본인의 SMB/파일 있는 위치를 Volumes 부분에 수정해서 사용하세요
