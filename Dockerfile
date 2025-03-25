FROM python:3.9-alpine3.18

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apk update && apk add --no-cache bash

# 파이썬 패키지 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 파일 복사
COPY socks5_server_full.py .

# 환경 변수 설정 (필요한 경우 Dockerfile에서 기본값 설정)
# 보안을 위해 실제 환경에서는 docker run 시에 -e 옵션으로 환경 변수를 전달하는 것이 좋습니다.
# 예시:
# ENV USERNAME_1=testuser
# ENV PASSWORD_1=testpassword
# ENV SOCKS_HOST=0.0.0.0
# ENV SOCKS_PORT=1080

# 서버 실행 명령
ENTRYPOINT ["python", "socks5_server_full.py"]

# 포트 노출 (프록시 서버 포트)
EXPOSE 1080
