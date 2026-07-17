FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend_app/ ./backend_app/
COPY waf/ ./waf/
COPY waf_settings.json ./waf_settings.json
COPY docker/entrypoint.sh ./docker/entrypoint.sh
RUN chmod +x ./docker/entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["./docker/entrypoint.sh"]
