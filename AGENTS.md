# Codex Context — Joe Pangallo's AI Infrastructure

## Who
Joe Pangallo runs **Ledd Consulting** (AI agent consulting, leddconsulting.com) and **MetalTorque** (builder identity, metaltorque.dev). GitHub: `joepangallo` (all repos private). Tampa Bay, FL.

## What's Been Built

A production AI infrastructure with:
- **48+ VPS microservices** (Ubuntu, IP 76.13.114.106) on ports 3004-3071 behind nginx + Cloudflare SSL
- **22 AI agents** on VPS managed by PM2, all using `claude -p` CLI for zero-cost LLM calls
- **1 Railway service** — Cloud Agent (Devin competitor, Slack bot, 7,700-line server.ts)
- **8 research swarms** with 32 sub-agents running nightly + 5 Gemini swarms for business automation
- **MT** — autonomous AI assistant on Telegram + Discord (Claude Haiku via OpenClaw gateway)
- **10 published npm packages** (5 CLIs + 5 MCP servers)
- **60+ systemd timers** for content, monitoring, swarms, trading, blog auto-posting
- **Event bus** (14 event types) + **Redis pub/sub** for real-time agent communication
- **ChromaDB memory layer** for MT (episodic/semantic/procedural, Ollama embeddings)
- **3 blog series** auto-posting daily to joepangallo.com (quantum, AI, software engineering)

**Zero-cost LLM strategy:** All Claude calls use `claude -p` CLI with subscription OAuth = $0 API cost.
## VPS Architecture (76.13.114.106)

**SSH:** `ssh root@76.13.114.106` (must use IP, domain goes through Cloudflare)
**Agents:** `/root/vps-agents/` | **Config:** `/home/openclaw/.openclaw/`
**Node path:** `/usr/local/bin/node` (NOT `/usr/bin/node`)
**Deploy:** `rsync -avz <local> root@76.13.114.106:/root/vps-agents/<path>`

### leddconsulting.com Subdomains (nginx)
| Subdomain | Service | Port |
|-----------|---------|------|
| leddconsulting.com | Main website (static HTML) | — |
| agent.leddconsulting.com | Cloud Agent (Railway proxy) | — |
| cloudagent.leddconsulting.com | Cloud Agent (alias) | — |
| audit.leddconsulting.com | MCP Security Audit (alias) | 3091 |
| mcpaudit.leddconsulting.com | MCP Security Audit | 3091 |
| pay.leddconsulting.com | AgentPay | 3065 |
| agentpay.leddconsulting.com | AgentPay (alias) | 3065 |
| marketplace.leddconsulting.com | MT Marketplace | 3004 |
| mcp.leddconsulting.com | Web Recon Agent MCP server | — |

### metaltorque.dev Subdomains (nginx)
| Subdomain | Service | Port |
|-----------|---------|------|
| consulting.metaltorque.dev | CRM/pipeline dashboard | — |
| signals.metaltorque.dev | Research Signal API | 3034 |
| audit.metaltorque.dev | Lead Magnet (Free AI Audit) | 3040 |
| status.metaltorque.dev | OmniAudit (monitoring) | 3043 |
| nexus.metaltorque.dev | Swarm Nexus (orchestrator) | 3046 |
| devgenius.metaltorque.dev | AI Automation Matcher | 3048 |
| indexforge.metaltorque.dev | IndexForge (SEO SaaS) | 3056 |
| analytics.metaltorque.dev | Agent Analytics | 3053 |
| observer.metaltorque.dev | Agent Observer | — |
| intel.metaltorque.dev | Ghost blog/newsletter | — |

### Core Services (ports 3004-3029)
| Port | Service | Purpose |
|------|---------|---------|
| 3004 | mt-marketplace | Agent marketplace API |
| 3005 | mcp-server | MCP server for marketplace |
| 3006 | mt-ipc | MT notification endpoint |
| 3007 | watcher-ipc | Task processing for Claude Code watcher |
| 3008 | contact-form | Lead capture + audit intake + Stripe webhook |
| 3009 | pipeline-api | CRM pipeline |
| 3010 | finance-tracker | Revenue/expense tracking |
| 3011 | api-analytics | Analytics collection |
| 3015 | event-bus | Central webhook routing (14 event types) |
| 3019 | agent-observer | Agent monitoring dashboard |
| 3024 | job-score | Job scoring + digest |
| 3025 | resume-match | ATS scoring + PDF rendering |
| 3027 | drift-detector | Z-score anomaly detection |
| 3099 | vps-control-api | Unified VPS control for MT Discord commands |

### AI Agents (ports 3030-3071)

**Data Product:** arxiv-to-poc (3030), content-flywheel (3031), job-positioning (3032), stack-watchtower (3033), research-signal-api (3034), pain-to-proposal (3049), wedge-finder (3050)

**Consulting Automation:** crm-prospector (3035), proposal-architect (3036), onboarding-officer (3037), reputation-sentinel (3038), client-pulse (3039), lead-magnet (3040), content-catalyst (3041)

**Meta-Agents:** synapse-forge (3042), omni-audit (3043), product-sculptor (3044), trust-weave (3045), swarm-nexus (3046), blog-forge (3047), dev-genius (3048), pitchforge (3057)

**Revenue:** agent-audit/web-security-scanner (3051), index-forge (3056), trade-agent (3063), agent-pay (3065), seo-autopilot (3066), mt-memory (3071)

**Auto-Created:** ports 3060+ generated on-the-fly by dev-genius.

### Shared Modules (`/root/vps-agents/shared/`)
| Module | Purpose |
|--------|---------|
| server.js | Express factory — health, webhooks, security headers, 127.0.0.1 binding, timing-safe auth |
| auth.js | API key extraction + HMAC webhook verification, fail-closed |
| claude.js | Claude CLI wrapper — `ask()`, `askJSON()`, `summarize()` |
| telegram.js | Telegram notifications |
| crm.js | CRM pipeline API client |
| event-bus.js | Central event bus pub/sub |
| analytics.js | Analytics tracking |

### Security
- All agents bind `127.0.0.1` — nginx proxies public access
- UFW (22/80/443), fail2ban, all nginx configs have full security headers
- **210-finding audit completed Feb 25 2026** — all remediated
- 3 auth keys: `INTERNAL_SECRET` (webhooks), `AGENT_AUTH_KEY` (endpoints), `AGENT_API_KEY` (Railway)
- All timing-safe, fail-closed
## Cloud Agent (Main Product)

Devin competitor — Slack-based AI dev tool on Railway.
**Stack:** `server.ts → Claude Agent SDK → Claude Code CLI → Claude API`
**URL:** agent.leddconsulting.com (Railway, proxied via VPS nginx)
**Source:** `cloud-agent-consulting/slack-agent/server.ts` (~7,700 lines)

**Commands:** `/agent <task>`, `/review <PR>`, `/ask <q> in <repo>`, `/test <file>`, `/scan [repos]`, `/analyze`
**Playbooks (7):** security-remediation, dependency-upgrade, docs-sync, bug-triage, test-coverage, code-migration, pr-review-cycle
**Integrations (16):** Slack, GitHub, Jira, Linear, Teams, Zendesk, Intercom, HubSpot, Monday, Asana, Notion, n8n, Zapier, Generic — all with HMAC signature verification + postback APIs
**Web pages:** `/playbooks` (management UI), `/usage` (client dashboard), `/teams` (marketing landing)

## Published npm Packages

| Package | Type | Tools/Commands |
|---------|------|----------------|
| `indexforge` | CLI | 18 commands — SEO indexing automation |
| `mcp-server-indexforge` | MCP | 11 tools — indexing_status, add_domain, scan_sitemap, etc. |
| `audit-metaltorque` | CLI | 20+ commands — security auditing |
| `mcp-server-security-audit` | MCP | 10 tools — security_scan, full_security_audit, etc. |
| `mt-analytics` | CLI | 7 commands — agent fleet analytics |
| `mcp-server-agent-analytics` | MCP | 7 tools — dashboard, insights, anomalies, etc. |
| `mt-signals` | CLI | 8 commands — research signal intelligence |
| `mcp-server-research-signals` | MCP | 6 tools — signals, trending, by_category, etc. |
| `mcp-server-agentpay` | MCP | 9 tools — wallets, tool provisioning, x402 USDC |
| `mcp-server-cloud-agent` | MCP | 5 tools — sessions, messages, status |

**CLI pattern:** Zero-dependency (Node builtins only), `--json` flag, env var auth.
**MCP pattern:** `@modelcontextprotocol/sdk`, StdioServerTransport, free-tier without API key.

## MT (MetalTorque) — Autonomous AI Assistant

- **Platforms:** Telegram (@MetalTorqueBot) + Discord (@MT, 6 channels)
- **Model:** Claude Haiku 4.5 via OpenClaw gateway (port 18789)
- **Mode:** Pure ideation — no sales, no outreach
- **Heartbeat:** Every 10 minutes
- **Memory:** ChromaDB (port 3071) — episodic/semantic/procedural with time decay
- **Discord commands:** `mt status`, `mt health`, `mt logs <service>`, `mt restart <service>`, `mt execute "<task>"`

## Swarm Pipeline (nightly 1 AM EST)

```
Phase 0: swarm-scraper.js (40 data sources — HN, Reddit, ArXiv, GitHub, etc.)
Phase 1: 3-4 Haiku explorers per swarm (8 swarms)
Phase 2: 1 Sonnet synthesizer per swarm
Post-processing: action-extractor → synthesizer → knowledge → ghost-publish → builder
```

**Swarms:** agent-monetization, client-acquisition, competitor-analysis, mcp-servers, agent-ai-ideas (daily); infinity, quantum-computing (weekly); target-companies (on-demand)
**Gemini swarms:** SaaS, ProServ, E-commerce, Enterprise ICPs — daily, emailed reports.

## Revenue Strategy

- **Consulting:** $200/hr dev, $250/hr strategy, $300/hr advisory. Retainer $2K-$5K/mo
- **SaaS:** IndexForge ($99-499/yr), MCP Security Audit ($19-149/mo), AgentPay ($10-600 credits)
- **Marketplace:** Agent credits, ~$125/week passive
## Key Repos

| Repo | Purpose |
|------|---------|
| joepangallo/cloud-agent-consulting | Cloud Agent template — 7,700-line server.ts, 9 webhook integrations, playbooks |
| joepangallo/cloud-agent-slack | Cloud Agent production (Railway) |
| joepangallo/vps-agents | 22 AI agent services (pm2, ports 3030-3071) |
| joepangallo/web-recon-agent | Security scanner + MCP server — v0.8.0, 40+ agents, 8 MCP tools |
| joepangallo/mcp-security-audit | Private audit engine — port 3091, 151 tests, Stripe, VPS ops |
| joepangallo/mcp-audit-server | Public npm audit proxy — ledd-mcp-audit-server@2.0.3, MCP Registry |
| joepangallo/web-security-scanner | Website security scanner — port 3051 |
| joepangallo/index-forge | SEO indexing SaaS — CLI + MCP + VPS agent |
| joepangallo/agent-analytics | Agent fleet analytics — CLI + MCP + VPS agent |
| joepangallo/research-signal-api | Research signals — CLI + MCP + VPS agent |
| joepangallo/agent-pay | Payment gateway — MCP + VPS agent, Stripe + x402 USDC |
| joepangallo/trade-agent | Coinbase crypto trading bot (paper mode) |
| joepangallo/claude-config | Claude Code config — CLAUDE.md, skills, settings |
| joepangallo/codex-config | Codex config — AGENTS.md context, sync script |
| joepangallo/openclaw-config | VPS workspace config — swarm scripts, VPS-SERVICES.md |
| joepangallo/leddconsulting.com | Public website (static HTML, VPS nginx) |
| joepangallo/joepangallo.com | Personal blog (3 auto-posting series, Hostinger) |
| joepangallo/mcp-server-cloud-agent | Cloud Agent MCP server (npm package) |
| joepangallo/railway-expert-guide | 20-chapter Railway mastery book |
| joepangallo/agentic-coding-book | Building Agentic AI Systems book |
| joepangallo/agent-challenges | 130-day agentic dev certification |

## Design System (Ledd Consulting)

```
BG: #09090b | Cards: #151519 | Border: #1c1c24
Accent: #6d5cff (purple) | Secondary: #10b981 (green)
Gradient: linear-gradient(135deg, #6d5cff, #10b981)
Text: #ececf1 | Muted: #a1a1aa
Font: -apple-system, Inter, system-ui, sans-serif
Radius: 12px | Transition: 0.2s ease
```

## Rules
- No Claude/Codex co-author lines in git commits
- All repos private by default
- Tests: vitest or node:test depending on repo, mock all external deps
