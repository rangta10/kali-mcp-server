#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

const server = new Server({
  name: "kali-security-tools",
  version: "2.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // Basic Network Tools
      {
        name: "nmap_scan",
        description: "Run an nmap port scan on a target IP or hostname. Can scan specific ports or ranges.",
        inputSchema: {
          type: "object",
          properties: {
            target: {
              type: "string",
              description: "Target IP address or hostname to scan"
            },
            ports: {
              type: "string",
              description: "Ports to scan (e.g., '80,443' or '1-1000')",
              default: "1-1000"
            },
            scan_type: {
              type: "string",
              description: "Scan type: 'fast', 'full', 'version', 'os'",
              default: "fast"
            }
          },
          required: ["target"]
        }
      },
      {
        name: "whois_lookup",
        description: "Perform WHOIS lookup for a domain to get registration info",
        inputSchema: {
          type: "object",
          properties: {
            domain: {
              type: "string",
              description: "Domain name to lookup"
            }
          },
          required: ["domain"]
        }
      },
      {
        name: "dig_dns",
        description: "Perform DNS lookup using dig command",
        inputSchema: {
          type: "object",
          properties: {
            domain: {
              type: "string",
              description: "Domain name to query"
            },
            record_type: {
              type: "string",
              description: "DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA)",
              default: "A"
            }
          },
          required: ["domain"]
        }
      },
      {
        name: "ping_host",
        description: "Ping a host to check connectivity and latency",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Host to ping"
            },
            count: {
              type: "number",
              description: "Number of ping packets to send",
              default: 4
            }
          },
          required: ["host"]
        }
      },
      {
        name: "netcat_connect",
        description: "Connect to a host and port using netcat for banner grabbing",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Target host"
            },
            port: {
              type: "number",
              description: "Target port"
            }
          },
          required: ["host", "port"]
        }
      },
      
      // Web Vulnerability Scanning
      {
        name: "nikto_scan",
        description: "Run Nikto web vulnerability scanner against a target URL",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL to scan (e.g., http://example.com)"
            },
            ssl: {
              type: "boolean",
              description: "Use SSL/HTTPS",
              default: false
            }
          },
          required: ["url"]
        }
      },
      
      // SQL Injection Testing
      {
        name: "sqlmap_scan",
        description: "Use SQLMap to test for SQL injection vulnerabilities",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL to test (e.g., http://example.com/page?id=1)"
            },
            method: {
              type: "string",
              description: "HTTP method: GET or POST",
              default: "GET"
            },
            data: {
              type: "string",
              description: "POST data if using POST method"
            }
          },
          required: ["url"]
        }
      },
      
      // Password Cracking
      {
        name: "hydra_bruteforce",
        description: "Use Hydra for password brute forcing (SSH, FTP, HTTP, etc.)",
        inputSchema: {
          type: "object",
          properties: {
            target: {
              type: "string",
              description: "Target IP or hostname"
            },
            service: {
              type: "string",
              description: "Service to attack (ssh, ftp, http-get, http-post, etc.)"
            },
            username: {
              type: "string",
              description: "Username to test (or 'wordlist' to use file)"
            },
            wordlist: {
              type: "string",
              description: "Path to password wordlist",
              default: "/usr/share/wordlists/rockyou.txt"
            }
          },
          required: ["target", "service", "username"]
        }
      },
      
      // DNS Enumeration
      {
        name: "dns_enum",
        description: "Perform DNS enumeration to find subdomains and DNS records",
        inputSchema: {
          type: "object",
          properties: {
            domain: {
              type: "string",
              description: "Target domain to enumerate"
            },
            wordlist: {
              type: "string",
              description: "Subdomain wordlist path",
              default: "/usr/share/wordlists/dnsmap.txt"
            }
          },
          required: ["domain"]
        }
      },
      
      // Subdomain Discovery
      {
        name: "subdomain_enum",
        description: "Discover subdomains using multiple methods (amass-style enumeration)",
        inputSchema: {
          type: "object",
          properties: {
            domain: {
              type: "string",
              description: "Target domain"
            },
            method: {
              type: "string",
              description: "Method: 'passive' (safe) or 'active' (includes brute force)",
              default: "passive"
            }
          },
          required: ["domain"]
        }
      },
      
      // SSL/TLS Analysis
      {
        name: "ssl_scan",
        description: "Analyze SSL/TLS configuration of a host",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Target hostname"
            },
            port: {
              type: "number",
              description: "Port number",
              default: 443
            }
          },
          required: ["host"]
        }
      },
      
      // Metasploit
      {
        name: "metasploit_search",
        description: "Search Metasploit database for exploits, payloads, or modules",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              description: "Search query (e.g., 'apache', 'windows smb', 'type:exploit platform:linux')"
            },
            type: {
              type: "string",
              description: "Module type: exploit, payload, auxiliary, post, encoder, nop",
              default: "all"
            }
          },
          required: ["query"]
        }
      },
      {
        name: "metasploit_exploit_info",
        description: "Get detailed information about a specific Metasploit module",
        inputSchema: {
          type: "object",
          properties: {
            module: {
              type: "string",
              description: "Full module path (e.g., exploit/windows/smb/ms17_010_eternalblue)"
            }
          },
          required: ["module"]
        }
      },
      
      // Social Engineering Toolkit
      {
        name: "set_info",
        description: "Get information about Social Engineering Toolkit capabilities and attack vectors",
        inputSchema: {
          type: "object",
          properties: {
            info_type: {
              type: "string",
              description: "Type of info: 'vectors', 'modules', 'payloads', 'help'",
              default: "vectors"
            }
          }
        }
      },
      
      // Additional Recon Tools
      {
        name: "traceroute",
        description: "Trace the network path to a host",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Target host"
            }
          },
          required: ["host"]
        }
      },
      {
        name: "host_discovery",
        description: "Discover live hosts on a network using nmap ping scan",
        inputSchema: {
          type: "object",
          properties: {
            network: {
              type: "string",
              description: "Network range in CIDR notation (e.g., 192.168.1.0/24)"
            }
          },
          required: ["network"]
        }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    let command;
    let result;

    switch (name) {
      // Basic Network Tools
      case "nmap_scan": {
        let scanOpts = "";
        switch (args.scan_type) {
          case "fast":
            scanOpts = "-F";
            break;
          case "full":
            scanOpts = "-p-";
            break;
          case "version":
            scanOpts = "-sV";
            break;
          case "os":
            scanOpts = "-O";
            break;
          default:
            scanOpts = "";
        }
        command = `nmap ${scanOpts} -p ${args.ports || "1-1000"} ${args.target}`;
        result = await execAsync(command, { timeout: 120000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      case "whois_lookup":
        command = `whois ${args.domain}`;
        result = await execAsync(command, { timeout: 30000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };

      case "dig_dns":
        command = `dig ${args.domain} ${args.record_type || "A"} +short`;
        result = await execAsync(command, { timeout: 10000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || "No records found"
          }]
        };

      case "ping_host":
        command = `ping -c ${args.count || 4} ${args.host}`;
        result = await execAsync(command, { timeout: 15000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };

      case "netcat_connect":
        command = `timeout 5 nc ${args.host} ${args.port}`;
        result = await execAsync(command, { timeout: 10000 }).catch(e => ({ 
          stdout: e.stdout || "Connection timeout", 
          stderr: e.stderr 
        }));
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr || "Connection failed"
          }]
        };

      // Web Vulnerability Scanning
      case "nikto_scan": {
        const sslFlag = args.ssl ? "-ssl" : "";
        command = `nikto -h ${args.url} ${sslFlag} -output /tmp/nikto_output.txt -Format txt && cat /tmp/nikto_output.txt`;
        result = await execAsync(command, { timeout: 300000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // SQL Injection Testing
      case "sqlmap_scan": {
        const dataParam = args.data ? `--data="${args.data}"` : "";
        command = `sqlmap -u "${args.url}" ${dataParam} --batch --answers="follow=N" --level=1 --risk=1 --threads=5`;
        result = await execAsync(command, { timeout: 300000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // Password Cracking
      case "hydra_bruteforce": {
        command = `hydra -l ${args.username} -P ${args.wordlist} ${args.target} ${args.service} -t 4 -V`;
        result = await execAsync(command, { timeout: 300000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // DNS Enumeration
      case "dns_enum": {
        // Using dnsrecon for DNS enumeration
        command = `dnsrecon -d ${args.domain} -t std`;
        result = await execAsync(command, { timeout: 60000 }).catch(e => ({
          stdout: e.stdout || "DNS enumeration completed",
          stderr: e.stderr
        }));
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // Subdomain Discovery
      case "subdomain_enum": {
        if (args.method === "passive") {
          // Using dig and common subdomains
          const subdomains = ["www", "mail", "ftp", "admin", "blog", "dev", "staging", "api"];
          const results = [];
          for (const sub of subdomains) {
            try {
              const res = await execAsync(`dig ${sub}.${args.domain} +short`, { timeout: 5000 });
              if (res.stdout.trim()) {
                results.push(`${sub}.${args.domain}: ${res.stdout.trim()}`);
              }
            } catch (e) {
              // Skip failed lookups
            }
          }
          return {
            content: [{
              type: "text",
              text: results.length > 0 ? results.join("\n") : "No subdomains found"
            }]
          };
        } else {
          // Active enumeration with dnsrecon
          command = `dnsrecon -d ${args.domain} -t brt -D /usr/share/wordlists/dnsmap.txt`;
          result = await execAsync(command, { timeout: 120000 }).catch(e => ({
            stdout: e.stdout || "Scan completed",
            stderr: e.stderr
          }));
          return {
            content: [{
              type: "text",
              text: result.stdout || result.stderr
            }]
          };
        }
      }

      // SSL/TLS Analysis
      case "ssl_scan": {
        command = `echo | openssl s_client -connect ${args.host}:${args.port || 443} -servername ${args.host} 2>&1 | openssl x509 -noout -text`;
        result = await execAsync(command, { timeout: 30000 }).catch(e => ({
          stdout: e.stdout || "SSL/TLS connection failed",
          stderr: e.stderr
        }));
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // Metasploit
      case "metasploit_search": {
        const typeFilter = args.type !== "all" ? `type:${args.type}` : "";
        command = `msfconsole -q -x "search ${typeFilter} ${args.query}; exit" 2>&1`;
        result = await execAsync(command, { timeout: 60000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      case "metasploit_exploit_info": {
        command = `msfconsole -q -x "info ${args.module}; exit" 2>&1`;
        result = await execAsync(command, { timeout: 30000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };
      }

      // Social Engineering Toolkit
      case "set_info": {
        let setInfo = "";
        switch (args.info_type) {
          case "vectors":
            setInfo = `Social Engineering Toolkit Attack Vectors:
1. Spear-Phishing Attack Vectors
2. Website Attack Vectors
3. Infectious Media Generator
4. Create a Payload and Listener
5. Mass Mailer Attack
6. Arduino-Based Attack Vector
7. Wireless Access Point Attack Vector
8. QRCode Generator Attack Vector
9. Powershell Attack Vectors
10. Third Party Modules

Note: SET requires interactive mode. This is informational only.`;
            break;
          case "modules":
            setInfo = `SET Module Categories:
- Social Engineering Attacks
- Penetration Testing (Fast-Track)
- Third Party Modules
- Update the Social-Engineer Toolkit
- Update SET configuration
- Help, Credits, and About

SET is designed for interactive use and requires user input for attack configuration.`;
            break;
          case "payloads":
            setInfo = `Common SET Payloads:
- Windows Reverse TCP Meterpreter
- Windows Reverse TCP VNC
- Windows Reverse TCP Shell
- Windows Bind TCP Meterpreter
- Import your own executable
- Backdoored executable

Payloads are typically delivered via phishing, infected media, or web exploits.`;
            break;
          default:
            setInfo = `Social Engineering Toolkit (SET) Help:
SET is an open-source penetration testing framework designed for social engineering.
It requires interactive mode and cannot be fully automated via MCP.

For interactive use, run: setoolkit

Common use cases:
- Phishing campaigns
- Credential harvesting
- Payload delivery
- Website cloning
- Mass mailer attacks`;
        }
        return {
          content: [{
            type: "text",
            text: setInfo
          }]
        };
      }

      // Additional Recon Tools
      case "traceroute":
        command = `traceroute ${args.host}`;
        result = await execAsync(command, { timeout: 60000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };

      case "host_discovery":
        command = `nmap -sn ${args.network}`;
        result = await execAsync(command, { timeout: 120000 });
        return {
          content: [{
            type: "text",
            text: result.stdout || result.stderr
          }]
        };

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: `Error executing ${name}: ${error.message}\n${error.stdout || ""}\n${error.stderr || ""}`
      }],
      isError: true
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
