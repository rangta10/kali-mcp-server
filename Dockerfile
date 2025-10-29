FROM kalilinux/kali-rolling

# Update and install essential tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    metasploit-framework \
    hydra \
    john \
    aircrack-ng \
    wireshark \
    tcpdump \
    netcat-traditional \
    dnsrecon \
    dnsutils \
    whois \
    traceroute \
    openssl \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    nodejs \
    npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy and install dependencies first
COPY package.json package-lock.json* ./
RUN npm install

# Copy server code
COPY server.js ./

# Create a startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'cd /app' >> /start.sh && \
    echo 'if [ ! -d "node_modules" ]; then npm install; fi' >> /start.sh && \
    echo 'node server.js' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 3000

CMD ["/start.sh"]
