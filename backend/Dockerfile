FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    ca-certificates curl git nmap golang-go \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/go/bin:${PATH}"

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

WORKDIR /workspace/backend

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt

COPY . .

VOLUME ["/workspace/output"]
