FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY plugins/shannon/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt

COPY plugins/shannon/main.py .

EXPOSE 8002

CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
