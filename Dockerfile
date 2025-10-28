# kali-mcp-server (by rangta)
FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
  nmap whois dnsutils netcat-traditional nikto sqlmap hydra dnsenum sslscan metasploit-framework set traceroute nodejs npm

WORKDIR /app
COPY . .
RUN npm install || true

CMD ["node", "server.js"]
