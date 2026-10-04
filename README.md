# 🛡️ SENTRY
**AI-Driven Continuous Threat Exposure Management (CTEM) Platform for Modern Intelligence Platforms**

**SENTRY** is a closed-loop security platform that discovers, validates, prioritizes, remediates, and verifies vulnerabilities across real-time intelligence platforms. It detects threats at the kernel level, proves exploitability safely inside disposable Digital Twin sandboxes, auto-drafts ready-to-deploy fixes, and confirms that every patch actually holds.

---

## 📌 Overview

Conventional security assessments treat applications as **isolated systems**, missing how real intelligence platforms actually fail.

Modern platforms ingest third-party feeds, expose APIs, run AI summarization, and ship code continuously. Attackers exploit the gaps *between* these components, not just the components themselves.

**SENTRY** is a **Modern CTEM stack** that closes this gap by combining kernel-level observability, AI payload sanitization, ephemeral sandboxing, static analysis, automated remediation, and cryptographic supply-chain verification into one continuous loop.

The platform continuously evaluates:

- 🔍 Unmonitored APIs, shadow IT, and risky third-party feeds
- 💉 Injection attempts (XSS, SSRF) hidden in untrusted data
- 🤖 Prompt injections targeting AI / LLM pipelines
- 🔗 Chains of low-severity flaws that combine into critical compromise
- 🔐 Role and permission combinations that enable privilege escalation
- 💸 Asymmetric API abuse driving up cloud costs (EDoS)
- 📦 Drift between running containers and signed CI/CD artifacts
- ✅ Whether "closed" vulnerabilities actually stay closed

> SENTRY never runs exploits against production. All validation happens in **temporary, anonymized clones**, and all generated fixes are raised as **pull requests for human review and merge**.

---

## ❗ Core Problem

| # | Problem | Impact |
|---|---------|--------|
| 1️⃣ | **Blind trust in data** — unvalidated third-party feeds allow injection attacks (XSS, SSRF) | Attackers inject fake alerts or malicious payloads **without bypassing authentication** |
| 2️⃣ | **Fragmented vulnerability findings** — scanners report flaws in isolation | Multiple low-severity flaws combine into a **critical security compromise** that goes unseen |
| 3️⃣ | **Unverified patches** — vulnerabilities are marked closed without regression testing or retest evidence | The same **CVE-class vulnerability silently reopens**, undetected until active exploitation |

---

## 🚀 Our Solution

**Discover → Validate → Prioritize → Remediate & Verify**

### 1. 📡 Always-On Blind-Spot Radar
Scans continuously in real time to uncover forgotten APIs, shadow IT, and risky third-party feeds **the moment they go live**.

### 2. 🧬 Digital Twin Sandboxing
Spins up temporary, disposable clones of the live application to safely test exploits. It proves the threat is real **without ever touching production users**.

### 3. 🎯 Context-Aware Prioritization
Drops generic 1–10 severity scores in favour of **business reality**. Threats are ranked on actual data sensitivity and active exploitability, so teams fix what matters most first.

### 4. 🛠️ Auto-Drafted Remediation
Replaces endless PDF audit reports with **ready-to-deploy code**. The system drafts the exact patch or firewall rule and pushes it directly into the developer's workflow.

### 5. ✅ Verify Closed-Loop Proof
Re-runs the validated exploit against the patched system, producing **clear proof** that the fix holds and the security gap is effectively closed.

---

## ⭐ Key Features & Novelty

### 1. 🧪 Defeating Data Poisoning
Blocks **"slow-drip" data injection** designed to skew real-time analytics and silently manipulate executive dashboards.

### 2. 🤖 AI & LLM Protection
Sanitizes inbound third-party feeds using **NeMo Guardrails** to prevent hidden prompt injections from hijacking AI summaries.

### 3. 💸 Cloud Billing Defense (EDoS)
Stops **Economic Denial of Sustainability** attacks, where attackers use lightweight requests to trigger massive, expensive backend queries.

### 4. 🔏 Zero-Drift Cryptography
Instantly catches **live code mutations** by verifying running containers against approved CI/CD cryptographic signatures (**Sigstore + OPA**).

### 5. 🎬 Digital Twin Playback
Safely proves complex attack chains by executing them against a **temporary, anonymized clone** of the live database.

### 6. 🕸️ Toxic Permission Mapping
Dynamically graphs role combinations to expose exactly how standard users could **daisy-chain minor access into admin control**.

---

## 🛠️ Technology Stack

### 🔭 Ingest & Detect
- eBPF (Kernel-level visibility)
- Cilium
- Tetragon
- Real-time network & API call monitoring

### 🧠 AI Security & Intelligence
- NeMo Guardrails (Semantic Shielding & Prompt Injection Defense)
- Semgrep AST Engine (Autonomous Code Patch Synthesis)
- AWS SageMaker & XGBoost (ML-based Attack Vector Forecasting)

### 🧬 Isolation & Sandboxing
- Kubernetes
- vcluster (Ephemeral virtual clusters)
- PCAP capture & sandbox logging

### ⚡ Event-Driven Backbone
- Apache Kafka — Asynchronous threat event streaming
- Redis — Low-latency triggers and state handoff
- Webhooks — Sandbox deployment triggers

### 🔐 Remediation & Supply Chain
- Semgrep (AST-based static analysis)
- Sigstore (Container image signing & verification)
- Open Policy Agent (OPA) — Patch and deployment policy enforcement
- GitHub / GitLab CI
- Infrastructure-as-Code (IaC) patch generation

---

## ⚙️ System Architecture

```
                    ┌───────────────────────────┐
                    │     ATTACK SURFACE        │
                    │                           │
                    │ APIs │ Third-Party Feeds  │
                    │ Containers │ AI Pipelines │
                    │ Roles & Permissions       │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   01 INGEST & DETECT      │
                    │    "The Listen Phase"     │
                    │                           │
                    │ eBPF (Cilium / Tetragon)  │
                    │ NeMo Guardrails           │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   EVENT-DRIVEN BACKBONE   │
                    │                           │
                    │ Kafka → Redis → Webhooks  │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   02 ISOLATE & ATTACK     │
                    │ "The Digital Twin Phase"  │
                    │                           │
                    │ vcluster Sandbox          │
                    │ Exploit Execution         │
                    │ Evidence (PCAP + Logs)    │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────┐
              │    CONTEXT-AWARE PRIORITIZATION        │
              │                                        │
              │ Data Sensitivity                       │
              │ Active Exploitability                  │
              │ Vulnerability Chaining                 │
              │ Toxic Permission Graph                 │
              └────────────────────┬───────────────────┘
                                   │
                                   ▼
                    ┌───────────────────────────┐
                    │   03 VERIFY & PATCH       │
                    │ "The Closed-Loop Phase"   │
                    │                           │
                    │ Semgrep (AST Engine)      │
                    │ LLM Patch + Pull Request  │
                    │ Sigstore + OPA            │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   CI/CD PIPELINE          │
                    │                           │
                    │ GitHub / GitLab CI        │
                    │ Human Review → Merge      │
                    │ Signed Build → Deploy     │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   CLOSED-LOOP PROOF       │
                    │                           │
                    │ Re-run Exploit            │
                    │ Confirm Verified Closure  │
                    └───────────────────────────┘
```

---

## 🔄 Architecture Workflow

### 1. Ingest & Detect — *"The Listen Phase"*

**eBPF: Kernel-Level Visibility (Cilium / Tetragon)**
- **Zero-Overhead Tracking** — Monitors network and API calls directly from the Linux kernel.
- **Real-Time Threat Mapping** — Instantly detects unusual processes bypassing firewalls.

**NeMo Guardrails: AI Payload Sanitization**
- **Semantic Shielding** — Blocks untrusted third-party data before it reaches the LLM.
- **Neutralizes Injections** — Actively filters malicious intent to prevent Indirect Prompt Injections.

### 2. Isolate & Attack — *"The Digital Twin Phase"*

**Goal:** Safely test exploits in a simulated cloud environment without affecting production data.

When a threat is detected, **vcluster** creates a temporary isolated sandbox. The exploit runs safely, evidence is captured, and the sandbox is immediately destroyed.

```
Spin Up Sandbox      →  Create an isolated namespace using vcluster
        ↓
Execute Exploit      →  Run the exploit inside the sandbox environment
        ↓
Capture Evidence     →  Collect logs and observe attacker behaviour
        ↓
Destroy Environment  →  Immediately remove the sandbox to eliminate risk
```

### 3. Context-Aware Prioritization

Instead of relying on a generic severity score, SENTRY ranks each validated threat using:

```
Data Sensitivity
      +
Active Exploitability (proven in sandbox)
      +
Vulnerability Chaining Potential
      +
Permission Escalation Paths
      ↓
Business-Risk Priority
```

### 4. Verify & Patch — *"The Closed-Loop Phase"*

**Cryptographic Drift Prevention** — Ensures only trusted, signed code runs in production.
- **Sigstore** — Signs container images in CI/CD and verifies artifacts before deployment.
- **Open Policy Agent (OPA)** — Enforces patch and deployment policies; blocks only non-compliant or unsigned containers.

**Auto-Generated Remediation Code** — Automatically turns detected vulnerabilities into fixes.
- **Semgrep** — Scans the codebase for known vulnerabilities and identifies the exact vulnerable code.
- **LLM Patch + Pull Request** — Generates the patch and creates a pull request for review and merge.

```
Vulnerability Detected
        ↓
Analyze & Verify
        ↓
Generate Fix
        ↓
Pull Request
        ↓
Test & Merge
        ↓
Patched in Production
```

### 5. Closed-Loop Verification

The validated exploit is **re-executed against the patched build**. Only when the exploit fails is the vulnerability marked as **Verified Closed**, preventing silent reopening of CVE-class issues.

---

## 🔁 SENTRY Workflow

```
DISCOVER   →  Map Attack Surface  →  Identify Entry Points (Auth, API)  →  Fingerprint Stack & Dependencies
                                                   ↓
VALIDATE   →  Reproduce in Sandbox  →  Chain Related Vulnerabilities  →  Capture Evidence (Requests / Responses)
                                                   ↓
REMEDIATE  →  Recommend Targeted Fixes  →  Patch & Retest  →  Confirm Verified Closure
```

---

## ⚡ Underlying Architecture: Event-Driven Execution Flow

### 1. Asynchronous Threat Triggers
```
eBPF  →  NeMo  →  Kafka  →  Redis  →  Deploy vcluster
```
eBPF and NeMo data flows through Kafka or Redis, triggering webhooks to quickly deploy the vcluster sandbox **without affecting production**.

### 2. Stateful Telemetry Handoff
```
Sandbox (PCAP + Logs)  →  Semgrep (AST Engine)
```
PCAP data and sandbox logs are sent to Semgrep's AST engine, giving it the context needed to generate the infrastructure code patch.

### 3. CI/CD Pipeline Hooking
```
IaC Patch (Generated)  →  GitHub / GitLab CI  →  Sigstore (Signing)
```
The patch is sent to GitHub / GitLab CI, which builds a new container, and Sigstore signs the verified image before deployment.

---

## 🔐 Security & Safety Principles

SENTRY follows a **safe-by-design, human-in-the-loop** remediation architecture.

### Production Isolation
- Exploits are **never** executed against production systems.
- Validation runs only inside ephemeral vcluster sandboxes.
- Sandboxes use **anonymized** data clones and are destroyed immediately after evidence capture.

### Human Authorization Layer
All auto-generated:
- Patches
- Firewall rules
- IaC changes
- Policy updates

are raised as **pull requests** and must be reviewed and merged by authorized engineers before reaching production.

### Supply-Chain Trust
```
Code Change
     │
     ▼
CI Build
     │
     ▼
Sigstore Signing
     │
     ▼
OPA Admission Policy
     │
     ├── Signed & Compliant  →  Deploy
     └── Unsigned / Drifted  →  Block
```

---

## 🧠 Core Intelligence Pipeline

SENTRY follows a closed-loop CTEM architecture:

```
LISTEN
  ↓
DETECT
  ↓
SANITIZE
  ↓
ISOLATE
  ↓
EXPLOIT (in sandbox)
  ↓
PRIORITIZE
  ↓
REMEDIATE
  ↓
SIGN
  ↓
DEPLOY
  ↓
VERIFY
  ↓
LEARN
```

This transforms raw kernel and application telemetry into **verified, closed-out security fixes**.

---

## 📐 Supply-Chain Enforcement Examples

**Signing and verifying a container image with Sigstore (cosign):**

```bash
cosign sign --key cosign.key registry.example.com/app:patched
cosign verify --key cosign.pub registry.example.com/app:patched
```

**Blocking unsigned images with an OPA policy (Rego):**

```rego
package sentry.admission

import rego.v1

deny contains msg if {
    input.request.kind.kind == "Pod"
    image := input.request.object.spec.containers[_].image
    not verified_images[image]
    msg := sprintf("Blocked: image %s is not signed or has drifted", [image])
}
```

**Spinning up and tearing down a Digital Twin sandbox:**

```bash
vcluster create sentry-sandbox-001 --namespace sandbox-001
# ... execute exploit and capture evidence ...
vcluster delete sentry-sandbox-001 --namespace sandbox-001
```

---

## 📊 The Predictive Edge: Proactive Defense

SENTRY learns continuously from its own validation history.

```
Historical Sandbox Telemetry
          +
Validated Exploit Chains
          +
Attack Surface Changes
          ↓
Attack Vector Forecasting (ML)
          ↓
Block the Next Likely Exploit Before It Occurs
```

The result moves security teams from **reacting to incidents** toward **predicting and pre-empting them**.

---

## 💻 Local Installation & Setup

### Run the source assessment workspace

From the repository root, install the Sentry dependencies and start the assessment API:

```bash
cd Sentry
npm install
npm run server
```

In a second terminal, start the development UI:

```bash
cd Sentry
npm run dev
```

The development server proxies `/api` requests to the assessment service. For a production-style local run, build the UI with `npm run build` and start `npm run server`; it serves the built UI and assessment API from the same origin.

### Prerequisites

Make sure the following are installed:

- Python 3.10+
- Docker
- Kubernetes cluster (kind / minikube for local development)
- kubectl & Helm
- vcluster CLI
- Semgrep
- cosign (Sigstore)

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/sentry.git
cd sentry
```

### 2. Install the Detection Layer (Tetragon)

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
```

### 3. Start the Event Backbone (Kafka + Redis)

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 4. Install Policy Enforcement (OPA Gatekeeper)

```bash
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace
kubectl apply -f policy/
```

### 5. Start the SENTRY Orchestrator

```bash
python -m venv venv
```

**Windows**
```bash
venv\Scripts\activate
```

**Linux / macOS**
```bash
source venv/bin/activate
```

```bash
pip install -r requirements.txt
python -m orchestrator.main
```

---

## 📁 Project Structure

```
SENTRY/
│
├── detect/
│   ├── tetragon-policies/
│   └── ebpf/
│
├── guardrails/
│   └── nemo-config/
│
├── orchestrator/
│   ├── main.py
│   ├── kafka_consumers/
│   ├── redis_triggers/
│   └── sandbox_controller/
│
├── sandbox/
│   ├── vcluster/
│   ├── exploits/
│   └── evidence/
│
├── prioritization/
│   ├── risk_scoring/
│   └── permission_graph/
│
├── remediation/
│   ├── semgrep-rules/
│   ├── patch_generator/
│   └── pr_bot/
│
├── policy/
│   └── opa/
│
├── supply-chain/
│   └── sigstore/
│
├── ml/
│   └── attack_forecasting/
│
├── deploy/
│   ├── helm/
│   └── docker-compose.yml
│
├── docs/
│
└── README.md
```

---

## 🎯 Problem → Solution

| Security Challenge | SENTRY Capability |
|--------------------|-------------------|
| Forgotten APIs and shadow IT | Always-On Blind-Spot Radar |
| Blind trust in third-party data | NeMo semantic shielding & data-poisoning defense |
| Prompt injection into AI summaries | AI & LLM Protection |
| Fragmented, isolated findings | Vulnerability chaining in sandbox |
| Generic 1–10 severity scores | Context-Aware Prioritization |
| Risky testing on live systems | Digital Twin Sandboxing (vcluster) |
| PDF audit reports nobody acts on | Auto-drafted patches as pull requests |
| Patches closed without retest | Closed-loop exploit re-verification |
| Live code mutation in production | Zero-Drift Cryptography (Sigstore + OPA) |
| Expensive-query API abuse | Cloud Billing (EDoS) Defense |
| Hidden privilege escalation paths | Toxic Permission Mapping |

---

## 🌱 Expected Impact

SENTRY is designed to help security and engineering teams:

- Discover exposed assets the moment they go live
- Block data poisoning and prompt injection before it reaches analytics or AI
- Prove real exploitability instead of chasing false positives
- Detect multi-step attack chains built from low-severity flaws
- Prioritize fixes by business impact, not generic scores
- Cut remediation time with ready-to-merge patches
- Guarantee that only signed, trusted code runs in production
- Prevent silent reopening of previously fixed vulnerabilities
- Reduce cloud cost exposure from EDoS-style abuse
- Maintain a verifiable, auditable trail of every fix

---

## 🔮 Future Scope

Potential extensions include:

- Reinforcement-learning-based autonomous red teaming
- Graph neural networks for attack-path prediction
- Multi-cloud and hybrid-cloud attack surface coverage
- Automated compliance mapping (ISO 27001, CERT-In guidelines)
- SBOM-driven dependency risk tracking
- Runtime auto-rollback on detected drift
- Federated threat intelligence sharing across organizations
- Deeper LLM red-teaming for AI-native applications
- Natural-language security copilot for SOC teams

---

## 👥 Core Team — MAVERICKS-25

| Team Member |
|-------------|
| Katkuri Harshitha Reddy |
| Sahas Reddy Billa |
| Charishma |
| Manish Reddy |
| Rajaneesh |
| Devaashish |

---

## 🏆 Smart India Hackathon 2026

Developed for the **Smart India Hackathon 2026**

- **Team:** MAVERICKS-25
- **Ministry / Organization:** `<to be added>`
- **Problem Statement:** `<SIH26XXX>`
- **Working Video:** `<YouTube link>`

---

## 📜 Project Philosophy

> **Listen to everything. Prove what's real. Fix what matters. Verify it stays fixed.**

SENTRY aims to bridge the gap between vulnerability discovery, exploit validation, remediation, and supply-chain trust through a unified, event-driven CTEM architecture.

---

## ⭐ SENTRY

**From Periodic Audits to Continuous, Verified Security.**.
