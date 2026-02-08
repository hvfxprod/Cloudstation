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
2. 접속: **http://서버IP:9999**
3. **Control Panel → 일반(General)** 에서 **Compose .env** 카드로 이동한 뒤,  
   **MOUNT_PATH**(호스트 마운트 경로), **TRUENAS_URL**, **TRUENAS_API_KEY**, **GEMINI_API_KEY** 등을 입력하고 **Save .env** 를 누르면 `data/.env` 파일이 생성·갱신됩니다.
4. env를 바꾼 뒤에는 컨테이너를 재시작해야 적용됩니다:  
   `docker compose up -d --force-recreate cloudstation`

- 컨테이너의 `/data`는 호스트의 `./data`와 연결됩니다. **MOUNT_PATH**에 다른 경로(예: NAS 마운트 경로)를 넣으면 SFTP/파일 루트로 사용됩니다. 같은 경로를 쓰려면 `MOUNT_PATH`를 `./data` 또는 `/data`로 두면 됩니다.
- **TrueNAS**: Health 탭에서 풀/디스크를 보려면 `TRUENAS_URL`, `TRUENAS_API_KEY`를 .env에 설정하세요.
- **AI Assistant**: `GEMINI_API_KEY`를 .env에 설정하세요.
