#!/usr/bin/env node
/*
 * kali-mcp-server
 * Copyright (c) 2025 rangta
 */

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
  capabilities: { tools: {} }
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      { name: "nmap_scan", description: "Run an nmap port scan" },
      { name: "whois_lookup", description: "WHOIS lookup" },
      { name: "dig_dns", description: "DNS lookup" },
      { name: "ping_host", description: "Ping host" },
      { name: "netcat_connect", description: "Netcat connect" },
      { name: "nikto_scan", description: "Nikto web scan" },
      { name: "sqlmap_scan", description: "SQLMap scan" },
      { name: "hydra_bruteforce", description: "Hydra brute force" },
      { name: "dns_enum", description: "DNS enumeration" },
      { name: "subdomain_enum", description: "Subdomain discovery" },
      { name: "ssl_scan", description: "SSL/TLS inspection" },
      { name: "metasploit_search", description: "Metasploit search" },
      { name: "metasploit_exploit_info", description: "Metasploit module info" },
      { name: "set_info", description: "Social Engineering Toolkit info" },
      { name: "traceroute", description: "Traceroute" },
      { name: "host_discovery", description: "Host discovery" }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let command;
    switch (name) {
      case "nmap_scan":
        command = `nmap -sV -A ${args.target}`;
        break;
      case "whois_lookup":
        command = `whois ${args.domain}`;
        break;
      default:
        throw new Error("Unknown tool: " + name);
    }
    const result = await execAsync(command, { timeout: 120000 });
    return { content: [{ type: "text", text: result.stdout || result.stderr }] };
  } catch (error) {
    return { content: [{ type: "text", text: `Error: ${error.message}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
