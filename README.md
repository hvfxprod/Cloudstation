<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/drive/1s6p1rDNAHO8xfzv-qiHOzl3Nr0CLz33_

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Docker 배포 (서버 + SMB 공유 연동)

**필요:** Docker, Docker Compose

1. 프로젝트 루트에서 빌드 및 실행:
   ```bash
   docker compose up -d --build
   ```
2. 호스트의 `/mnt/Theh_1/SMB_Share` 경로가 컨테이너 내부 `/data`로 마운트됩니다.  
   File Station의 **My Drive**가 이 경로의 파일/폴더를 표시합니다.
3. 접속: **http://서버IP:9000** (포트 9000)

환경 변수(선택):
- `DATA_PATH`: 컨테이너 내부 데이터 경로 (기본값: `/data`)
- `PORT`: 서버 포트 (기본값: `9000`)

다른 호스트 경로를 쓰려면 `docker-compose.yml`의 `volumes`를 수정하세요.
