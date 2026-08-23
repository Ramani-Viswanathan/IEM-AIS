# IEM-AIS Blueprint
## Intelligence Engineering Methodology — AI Security Assurance
### Version 1.0.0 · August 2026

---

## 1. Purpose

IEM-AIS is the **AI Security discipline** of the Intelligence Engineering Methodology.

Its purpose is to determine whether an AI-enabled system can be defended against security threats across its application, model, data, retrieval, agent, tool, infrastructure, identity, and supply-chain boundaries.

**Primary question:**

> **Can this AI system withstand, detect, contain, and recover from security threats?**

IEM-AIS evaluates technical security.

It does **not** own organizational AI governance or Responsible AI judgments about fairness, dignity, human autonomy, transparency, or social impact.

### Discipline boundary

| Discipline | Primary question | Primary object |
|---|---|---|
| **IEM-AIG** | Can the organization govern AI? | Organization / governance |
| **IEM-AIS** | Can the AI system withstand security threats? | Application / model / agent / infrastructure |
| **IEM-RAI** | Does the AI system treat people and society responsibly? | AI system + affected people |

---

## 2. Security Scope

IEM-AIS covers:

- LLM applications
- RAG systems
- AI APIs
- agents
- multi-agent systems
- tool-calling
- MCP-connected systems
- model gateways
- vector databases
- AI data pipelines
- model supply chains
- AI infrastructure
- application security around AI

It covers both:

1. **static security evidence**, and
2. **deterministic technical probes**.

---

## 3. What IEM-AIS Is Not

IEM-AIS is not:

- a general corporate cybersecurity audit;
- a SOC replacement;
- a penetration-testing certification;
- an AI governance system;
- a Responsible AI fairness assessment;
- a legal compliance certification.

Traditional infrastructure/security controls may be relevant evidence, but IEM-AIS focuses on **security risks introduced, amplified, or materially changed by AI systems**.

---

## 4. Security Threat Model

Every IEM-AIS audit begins by defining the attack surface.

```text
User
  ↓
Application
  ↓
Prompt / Input
  ↓
LLM
  ↓
RAG / Vector Store
  ↓
Tools / APIs / MCP
  ↓
Agent
  ↓
Enterprise Systems
  ↓
External Services
```

Across the lifecycle:

```text
Data → Training/Fine-tuning → Model → Application → Runtime → Tools → Output
```

Security assessment must consider:

- confidentiality
- integrity
- availability
- privilege
- authorization
- isolation
- provenance
- attackability
- abuse resistance
- recovery

---

## 5. IEM-AIS Security Domains

### S1 — Prompt & Instruction Security

- direct prompt injection
- indirect prompt injection
- jailbreaks
- system prompt leakage
- instruction hierarchy attacks
- malicious context

### S2 — RAG & Knowledge Security

- RAG poisoning
- malicious documents
- unauthorized retrieval
- tenant isolation
- retrieval authorization
- vector-store manipulation
- embedding attacks
- source integrity

### S3 — Output & Application Security

- insecure output handling
- generated code execution
- XSS/SQL injection through generated output
- unsafe downstream interpretation
- command injection
- unsafe serialization

### S4 — Agent & Tool Security

- excessive agency
- unauthorized tool use
- privilege escalation
- tool poisoning
- tool parameter manipulation
- agent identity
- action boundaries
- human approval bypass

### S5 — Data & Privacy Security

- sensitive information disclosure
- prompt leakage
- data exfiltration
- training-data extraction
- cross-tenant leakage
- secrets exposure

### S6 — Model Security

- model theft
- model extraction
- model tampering
- unauthorized model access
- model integrity
- inference abuse

### S7 — Availability & Resource Security

- denial of service
- unbounded consumption
- token exhaustion
- resource exhaustion
- cost abuse
- rate-limit bypass

### S8 — AI Supply Chain Security

- third-party model risk
- malicious packages
- model artifacts
- datasets
- dependencies
- plugins
- model provenance
- compromised providers

### S9 — Infrastructure & Identity

- API authentication
- authorization
- secrets
- network isolation
- tenant isolation
- logging
- encryption
- deployment security

### S10 — Detection, Response & Recovery

- security logging
- alerting
- incident response
- containment
- rollback
- model replacement
- evidence preservation
- recovery testing

---

## 6. Security Standards Library

### Primary

**OWASP Top 10 for LLM Applications**

Use the current declared OWASP release as the application security baseline. OWASP's 2025 list includes areas such as prompt injection, sensitive information disclosure, excessive agency, vector/embedding weaknesses, system prompt leakage, and unbounded consumption. citeturn0search37

**OWASP Agentic / agent security guidance**

Use for autonomous and tool-using systems.

### Supporting

- NIST AI RMF Secure and Resilient
- NIST AI RMF GenAI Profile
- NIST adversarial machine learning resources
- applicable application/cloud security standards
- organizational security requirements

NIST identifies security and resilience as one of the trustworthiness characteristics, including protection of confidentiality, integrity and availability and resilience against unexpected or adversarial use. citeturn0search1turn0search8

---

## 7. Security Evidence Model

### Static evidence

- architecture diagrams
- API specifications
- model inventory
- model/provider information
- permission matrices
- identity configuration
- network diagrams
- RAG architecture
- vector-store configuration
- tool registry
- MCP configuration
- security policies
- logs
- incident records
- SBOM/dependency data
- vendor security evidence

### Dynamic evidence

Probe results generated by deterministic test harnesses.

Required fields:

- probe name
- target
- timestamp
- configuration
- test category
- test cases
- attempts
- successful attacks
- success rate
- evidence samples
- severity
- limitations

---

## 8. Probe Architecture

```text
Probe
  ↓
Declared target
  ↓
Isolated subprocess
  ↓
Deterministic test suite
  ↓
Immutable JSON evidence
  ↓
IEM judgment layer
```

The LLM judge does not execute attacks.

The probe executes the test.

The judge interprets the resulting evidence.

The deterministic engine validates the final manifest and score.

---

## 9. Built-in Probe Families

### P01 — Prompt Injection

Test:

- direct injection
- indirect injection
- contextual injection
- instruction override

### P02 — Jailbreak

Test:

- policy bypass
- role-play bypass
- encoding
- multi-turn escalation
- adversarial reformulation

### P03 — RAG Poisoning

Test:

- malicious document insertion
- retrieval manipulation
- instruction-bearing documents
- source ranking manipulation
- cross-tenant retrieval

### P04 — Sensitive Information Disclosure

Test:

- secrets
- PII
- system prompts
- internal instructions
- unauthorized context

### P05 — Agent/Tool Abuse

Test:

- unauthorized tools
- excessive permissions
- parameter manipulation
- action escalation
- approval bypass

### P06 — Output Handling

Test:

- generated executable content
- unsafe downstream interpretation
- injection into consuming systems

### P07 — Availability

Test within safe, bounded limits:

- token abuse
- request amplification
- resource exhaustion
- rate-limit behavior

### P08 — Model/API Access

Test:

- authentication
- authorization
- model endpoint exposure
- tenant isolation
- privilege boundaries

---

## 10. Security Testing Rules

1. Read-only by default.
2. Explicit target required.
3. No production mutation.
4. Rate and resource limits required.
5. Destructive tests require explicit authorization.
6. Probe evidence is immutable.
7. Test credentials must be scoped.
8. Findings must distinguish vulnerability from theoretical risk.
9. Security evidence must identify the tested version/configuration.
10. A failed probe is not automatically proof of absence of a vulnerability; test coverage and limitations must be recorded.

---

## 11. IEM Seven Security Gaps

| Gap | Security example |
|---|---|
| **Missing** | No prompt-injection defense exists |
| **Ignored** | Security control exists but is bypassed |
| **Disconnected** | Security alert is generated but never reaches incident response |
| **Untrusted** | Vendor claims isolation but no evidence verifies it |
| **Underutilized** | Red-team results are collected but never used for remediation |
| **Misclassified** | Critical agent tool is treated as low privilege |
| **Divergent** | Architecture says human approval is required but runtime permits direct action |

### Trace order

`Capture → Integration → Definition/Taxonomy → Ownership → Process/Cadence → Tooling → Behavior`

---

## 12. Security Root Origins

1. **Capture** — security control was never implemented.
2. **Integration** — control exists but is not connected to the attack path.
3. **Definition / Taxonomy** — wrong security boundary or risk category.
4. **Ownership** — no accountable security owner.
5. **Process / Cadence** — security testing/review occurs incorrectly.
6. **Tooling** — chosen control/tool cannot protect the required architecture.
7. **Behavior** — people bypass or disable security controls.

---

## 13. State Machine

### Stage 0 — Baseline

Load declared security standards.

### Stage 1 — Security Charter

Define:

- systems
- targets
- attack boundaries
- authorization
- test limitations
- risk tolerance

### Stage 2 — Define

Convert applicable security requirements into testable criteria and required evidence.

### Stage 3 — Measure

1. ingest static evidence;
2. execute authorized probes;
3. freeze probe evidence;
4. correlate static and dynamic evidence.

### Stage 4 — Classify

Assign one IEM security gap.

### Stage 5 — Trace

Assign one root origin.

### Stage 6 — Engineer & Score

Recommend fix-at-source remediation.

### Stage 7 — Synthesize

Create the Audit Manifest.

### Stage 8 — Validate

Deterministic schema validation.

### Stage 9 — Render

Generate deterministic reports.

### Stage 10 — Finalize

Produce security summary, limitations and retest plan.

---

## 14. Severity Model

Security severity should consider:

### Harm

What can happen?

### Exposure

How many systems/users/data assets are affected?

### Exploitability

How easily can the attack be reproduced?

### Privilege

What authority can the attacker obtain?

### Persistence

Can the attacker maintain access or influence?

The final severity remains:

- Minor
- Moderate
- Major
- Critical

The scoring engine must remain deterministic.

---

## 15. Security Assurance Score

The score is **not a guarantee of security**.

It represents the evidence-backed security posture observed during the defined test.

Suggested dimensions:

- Attack surface coverage
- Preventive controls
- Detection
- Isolation
- Authorization
- Resilience
- Probe results
- Remediation status
- Evidence quality

Always display:

- tested scope
- untested scope
- test date
- model/version
- configuration
- probe coverage
- limitations

---

## 16. Required Finding Structure

```text
Finding F-AIS-001

Gap Type:
Root Origin:
Standard:
Security Domain:
System Component:
Attack Vector:

Evidence:
- Probe
- Target
- Timestamp
- Success rate
- Evidence sample

Impact:
Exploitability:
Privilege:
Severity:

Remediation:
Owner:
Retest:
```

---

## 17. Architecture

```text
iem-ais/
├── skills/
│   └── intelligence-engine-ais/
│       └── SKILL.md
├── iem_ais/
│   ├── core/
│   │   ├── engine.py
│   │   ├── manifest.py
│   │   ├── scoring.py
│   │   └── schema.py
│   ├── standards/
│   │   ├── owasp_llm.py
│   │   ├── owasp_agentic.py
│   │   └── nist_ai_security.py
│   ├── probes/
│   │   ├── prompt_injection.py
│   │   ├── jailbreak.py
│   │   ├── rag_poisoning.py
│   │   ├── privacy_extraction.py
│   │   ├── agent_abuse.py
│   │   └── availability.py
│   └── reports/
```

---

## 18. Implementation Phases

| Phase | Deliverable |
|---|---|
| P0 | Copy and verify IEM engine |
| P1 | IEM-AIS SKILL.md |
| P2 | OWASP LLM baseline |
| P3 | Prompt injection + jailbreak probes |
| P4 | RAG security probes |
| P5 | Sensitive information disclosure |
| P6 | Agent/tool security |
| P7 | Supply-chain assessment |
| P8 | NIST security mapping |
| P9 | Security delta/retest |
| P10 | v1 release |

---

## 19. Core Principles

1. Security testing requires authorization.
2. Test the system that actually exists, not only its documentation.
3. Probes produce evidence; the judge interprets evidence.
4. Never allow the judgment model to execute arbitrary security actions.
5. Security findings require reproducible evidence.
6. Retest after remediation.
7. Security posture is bounded by tested scope.
8. Same IEM engine, different security judgment layer.

---

## 20. Relationship to IEM-AIG and IEM-RAI

```text
IEM-AIG
  └── "Are we governing AI?"

IEM-AIS
  └── "Can attackers compromise AI?"

IEM-RAI
  └── "Are people and society treated responsibly by AI?"
```

A single AI system may therefore receive three separate assessments.

**Example: hiring AI**

- AIG → ownership, policy, approval, lifecycle governance
- AIS → API, access control, prompt injection, data leakage
- RAI → fairness, discrimination, explainability, candidate transparency, human agency

The disciplines may share evidence, but their judgments remain separate.

---

**Version:** 1.0.0  
**Ratified:** [Pending]  
**Author:** Ramani Viswanathan  
**Next Review:** After first security laboratory validation
