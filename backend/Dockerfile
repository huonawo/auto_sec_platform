FROM kalilinux/kali-rolling:latest

RUN sed -i 's|http://mirrors.neusoft.edu.cn/kali|https://mirrors.tuna.tsinghua.edu.cn/kali|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --fix-missing \
    python3 python3-pip \
    nmap \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/backend
ENV PYTHONPATH=/workspace/backend

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt

# Copy ProjectDiscovery binaries AFTER pip to avoid being overwritten by httpx Python package
COPY tools/nuclei /usr/local/bin/nuclei
COPY tools/httpx /usr/local/bin/httpx
RUN chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx

COPY . .

VOLUME ["/workspace/output"]
