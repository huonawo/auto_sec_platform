FROM kalilinux/kali-rolling:latest

RUN echo "deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    python3 python3-pip git curl wget \
    nmap metasploit-framework \
    bloodhound impacket-scripts \
    ruby ruby-dev build-essential golang-go \
    unzip zip graphviz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /workspace/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r /workspace/requirements.txt

WORKDIR /workspace

VOLUME ["/workspace/output"]
