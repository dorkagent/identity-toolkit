# MCP Tool-Permission Review: Checklist + Threat Model

A practical procedure for answering the question every enterprise AI-agent
deployment has to answer before go-live: **what can this agent actually do,
as whom, and who would notice if it went wrong?**

Work through it per MCP server. One pass per server, findings feed the same
remediation backlog as the identity risk review.

## Step 1: Inventory the MCP servers and their tools

For each MCP server the agent can reach, record:

- **Server**: name, version, who runs it (first-party, vendor, community).
- **Transport**: stdio (local process) or HTTP/SSE (network). Network
  transports get auth scrutiny; local ones get supply-chain scrutiny.
- **Authentication**: how the server authenticates the agent, and whose
  credentials it uses downstream (its own service identity, the end user's
  token, a shared key).
- **Tools exposed**: every tool name plus its description. The description
  is part of the attack surface (see threat model).
- **Data classification per tool**: for each tool, what its inputs can
  carry and what its outputs can return (public, internal, confidential,
  regulated). If you cannot classify a tool's outputs, treat them as
  confidential until proven otherwise.

## Step 2: Per-tool least-privilege review

For each tool, check:

- [ ] **Need**: does the agent's job actually require this tool? Remove
  what is not needed; an unexposed tool cannot be abused.
- [ ] **Read vs write**: read-only tools are the default. Any tool that
  writes, deletes, sends, or approves needs a named justification.
- [ ] **Scope**: is the tool scoped to the resources the agent needs
  (named repos, named mailboxes, named projects), or does it take
  arbitrary identifiers and act on anything?
- [ ] **Destructive actions**: does a write/delete/send tool require an
  explicit confirmation step, or does it fire on the agent's say-so?
- [ ] **Input validation**: are tool inputs validated server-side, or does
  the server trust whatever the agent passes?
- [ ] **Output handling**: can tool outputs contain attacker-controlled
  content (file contents, web pages, ticket bodies)? If yes, outputs are
  untrusted input to the agent (see prompt injection below).
- [ ] **Identity**: which identity does the tool act as, and is that
  identity's power proportionate to the agent's job?

## Step 3: Identity separation

- The **agent's identity**, the **MCP server's identity**, and the
  **end user's identity** are three different things. Write down which is
  which for every server. If you cannot, that is a finding.
- No shared credentials between agents. One agent, one identity; compromise
  of one agent must not mean compromise of the fleet.
- The agent must never act with broader permissions than the user who
  invoked it (no privilege laundering through the agent).

## Threat model (STRIDE-style)

| Threat | STRIDE | What it looks like | Mitigation |
|---|---|---|---|
| Prompt injection via tool descriptions or tool outputs | Tampering | A tool description or a fetched document contains instructions; the agent follows them as if they were the user's | Treat tool descriptions and outputs as untrusted data; review descriptions in Step 1; prefer servers that mark output provenance |
| Excessive tool permissions | Elevation of privilege | Agent has a file-write or admin tool "just in case"; a confused or hijacked agent uses it | Step 2 review; remove unneeded tools; scope the rest |
| User/agent identity confusion | Spoofing | Agent acts with the invoking user's broad permissions, or one agent's credentials are reused by another | Step 3 separation; per-agent identities; no shared keys |
| Tool calls not attributable | Repudiation | Something changed and nobody can say which agent, which tool, which identity did it | Log every tool call with timestamp, agent identity, tool name, arguments hash; keep the logs where the agent cannot rewrite them |
| Data exfiltration through tool outputs | Information disclosure | Agent with a "summarize this inbox" tool is steered to exfiltrate via a crafted message | Data classification per tool (Step 1); egress review on tools that reach outside the trust boundary |
| Malicious or compromised MCP server | Tampering / Spoofing | Community server update adds a credential-harvesting tool; agent happily calls it | Pin server versions; review changelogs; prefer first-party or vendored servers for sensitive tools |
| Resource exhaustion / runaway agent | Denial of service | Agent loops on an expensive tool; API quota or budget burns | Per-tool rate limits and call budgets; kill switches on long-running agent sessions |

## Remediation priority

1. Remove tools the agent does not need (cheapest, highest leverage).
2. Split or scope write/delete/send tools; add confirmation for destructive
   actions.
3. Give each agent its own identity; separate it from the user's identity.
4. Turn on tool-call audit logging with identity attached.
5. Then work the findings the identity risk review produced, critical first.
