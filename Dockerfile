FROM python:3.12-slim
RUN apt-get update && \
    apt-get install -y build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=app.py
ENV PORT 5000
