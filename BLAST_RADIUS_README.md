# ShieldDesk™ — Simulate Blast Radius Engine
### *Predictive Multi-Layer Vulnerability Impact & Operational Posture Modeling*

---

## 1. Executive Summary

In traditional Security Operations Centers (SOCs), vulnerability assessment is often limited to static metrics like CVSS base scores (e.g., `CVSS 9.3`). While numerical scores indicate severity, they fail to answer the most urgent operational question facing incident responders:

> **"If an attacker exploits this vulnerability right now, how far does the compromise spread, what services collapse, and which corporate assets are at immediate risk?"**

The **ShieldDesk Simulate Blast Radius Engine** provides real-time, deterministic, and predictive impact modeling for known vulnerabilities (CVEs) and affected assets. It translates threat intelligence into an architectural blast radius spanning **four structural layers**:

1. **Initial Vector** *(How the attacker achieves initial entry)*
2. **Process Layer** *(How the runtime application process and memory are compromised)*
3. **Host System** *(The privileges, files, and credentials seized on the local endpoint)*
4. **Network Layer** *(The horizontal lateral movement pathways into databases and internal subnets)*

---

## 2. Structural Architecture (The 4 Attack Layers)

```
+------------------------------------------------------------------------------------------------+
|                                    BLAST RADIUS IMPACT TIERS                                   |
+------------------------------------------------------------------------------------------------+
|                                                                                                |
|  1. INITIAL VECTOR       Attacker delivery payload (Phishing, ActiveX, Open Port, Exploit URL) |
|         │                                                                                      |
|         ▼                                                                                      |
|  2. PROCESS LAYER        Instruction pointer hijack, Buffer Overflow, Shell injection (/bin/sh)|
|         │                                                                                      |
|         ▼                                                                                      |
|  3. HOST SYSTEM          Endpoint privilege level (Local Admin, root, service account, token)  |
|         │                                                                                      |
|         ▼                                                                                      |
|  4. NETWORK LAYER        Subnet traversal, DB exposure, session pivoting to core infrastructure |
|                                                                                                |
+------------------------------------------------------------------------------------------------+
```

| Layer | Definition | Representative Example (`CVE-2007-4475`) |
| :--- | :--- | :--- |
| **Initial Vector** | The vector used by the threat actor to deliver the exploitation payload against the target surface. | Web navigation via Internet Explorer targeting unpatched SAP ActiveX control method `SaveViewToSessionFile`. |
| **Process Layer** | The immediate impact on the execution thread, memory layout, and runtime binary space. | Stack-based buffer overflow resulting in arbitrary binary code execution under the context of `iexplore.exe` or `saplogon.exe`. |
| **Host System** | The scope of local control, privilege elevation, filesystem manipulation, and persistence on the operating system. | Execution inherits the local desktop user's privileges. If running as Local Administrator, yields full registry and credential access. |
| **Network Layer** | The potential for horizontal pivoting, cross-subnet lateral reconnaissance, and downstream data exfiltration. | Confined to the workstation initially; expands horizontally only if active SAP session tokens or domain credentials can be dumped. |

---

## 3. End-to-End Implementation Workflow

The blast radius simulation operates across the full ShieldDesk stack:

```
                  Analyst Message: "Simulate Blast Radius for CVE-2024-6387"
                                             │
                                             ▼
                             +───────────────────────────────+
                             |       src/app/api/chat        |
                             |           route.ts            |
                             +───────────────────────────────+
                                             │
                       [1] Intent & Argument Extraction (BLAST_RADIUS_RE)
                       [2] RBAC Verification: Globex Analyst Persona Required
                                             │
                                             ▼
                             +───────────────────────────────+
                             |      src/lib/tools/           |
                             |   shieldDeskChatTools.ts      |
                             +───────────────────────────────+
                                             │
                       [3] Query Vulnerability Intelligence KB (12,968 CVEs)
                       [4] Evaluate Curated Profiles vs. Dynamic Rule Synthesis
                       [5] Compute Posture Downgrade Delta & Compliance Impact
                                             │
                                             ▼
                             +───────────────────────────────+
                             |   Output Formatting Engine    |
                             |  (Point-wise Markdown Stream) |
                             +───────────────────────────────+
                                             │
                                             ▼
                             +───────────────────────────────+
                             |       src/components/         |
                             |  FormattedAssistantMessage.tsx|
                             +───────────────────────────────+
                                             │
                       [6] Render Circular Sequence Numbers (1, 2, 3, 4)
                       [7] Render Colored Status Badges ([CRITICAL], [HIGH], etc.)
                       [8] Render Inline Code Pills & Warning Governance Banner
```

---

## 4. Core Implementation Files

### 4.1. Tool Gateway & Domain Logic ([`shieldDeskChatTools.ts`](file:///D:/mario/mINTS/ShieldDesk/UpdatedMainBranch/SHIELD-DESK/src/lib/tools/shieldDeskChatTools.ts))

The simulation engine is implemented in `simulateBlastRadius()`:

- **Persona Isolation Gate**:
  ```ts
  const isGlobex =
    session.tenantId === "globex-tenant" ||
    session.uid === "dev-other" ||
    session.email?.endsWith("@globex.corp");

  if (!isGlobex) {
    return { error: "not_authorized" };
  }
  ```
- **Context Resolution**: Resolves target CVE and target asset from the conversation session or linked incident ID.
- **Benchmark Profiles**: High-fidelity architectural models for industry-standard reference CVEs:
  - `CVE-2007-4475`: SAP ActiveX Stack Buffer Overflow (`webviewer3d.dll`)
  - `CVE-2018-2412`: SAP Disclosure Management 10.1 Missing Authorization (`CWE-862`)
  - `CVE-2018-14860`: Odoo Community/Enterprise Dynamic Expression Command Injection (`CWE-78`)
  - `CVE-2024-6387`: OpenSSH Signal Handler Race Condition (`regreSSHion` to `root`)
- **Dynamic Rule Engine (`generateDynamicBlastRadius`)**: Evaluates arbitrary CVE records using:
  - **CVSS Score scaling** (CVSS ≥ 9.0 $\rightarrow$ `Critical`, CVSS ≥ 7.0 $\rightarrow$ `High`, CVSS ≥ 4.0 $\rightarrow$ `Medium`, CVSS < 4.0 $\rightarrow$ `Low`).
  - **CWE taxonomy** (`CWE-119` memory corruption, `CWE-78` OS command injection, `CWE-862` authorization bypass, `CWE-79` XSS).
  - **Posture Degradation Formula**: Computes pre-breach vs. post-breach posture (e.g. `A- (91%)` $\rightarrow$ `C+ (68%)`, `-23% degradation`).
  - **Compliance Controls**: Maps impact to SOC 2 CC6.1, ISO 27001 A.12.1.2, PCI-DSS Req 6.2, and SOX 404.

### 4.2. Intent Routing & Guardrails ([`route.ts`](file:///D:/mario/mINTS/ShieldDesk/UpdatedMainBranch/SHIELD-DESK/src/app/api/chat/route.ts))

- **Regex Intent Interceptor**:
  ```ts
  const BLAST_RADIUS_RE = /\b(blast\s*radius|posture\s*(downgrade|simulation)|simulate\s*blast|impact\s*scope)\b/i;
  ```
- **Point-Wise Response Formatting**: Converts structured layer data into a numbered markdown sequence:
  ```markdown
  Simulated Blast Radius Assessment for **CVE-XXXX**:

  Target Asset & Scope: **srv-prod-api-01**

  1. **Initial Vector** [CRITICAL] — Exploit scope...
  2. **Process Layer** [HIGH] — Runtime memory scope...
  3. **Host System** [MEDIUM] — Host privilege scope...
  4. **Network Layer** [LOW-TO-MEDIUM] — Lateral movement scope...

  Governance Note: Blast radius simulations are predictive models. Tier 2 host isolation requires human analyst authorization.
  ```

### 4.3. UI Presentation Layer ([`FormattedAssistantMessage.tsx`](file:///D:/mario/mINTS/ShieldDesk/UpdatedMainBranch/SHIELD-DESK/src/components/ai-chat/FormattedAssistantMessage.tsx))

- **Numbered Step Badges**: Formats `1. `, `2. ` into deep pine circular badges (`bg-[var(--sd-pine)] text-[#f7f4ed]`).
- **Severity Tag Badges**:
  - `[CRITICAL]`: Red container (`bg-red-50 text-red-700 border-red-200`) with `<ShieldAlert />` icon.
  - `[HIGH]`: Orange container (`bg-amber-50 text-amber-800 border-amber-200`) with `<AlertTriangle />` icon.
  - `[MEDIUM]`: Neutral raised container with `<Info />` icon.
  - `[LOW-TO-MEDIUM]`: Light blue container (`bg-blue-50 text-blue-700 border-blue-200`) with `<Info />` icon.
  - `[LOW]`: Emerald container (`bg-emerald-50 text-emerald-700 border-emerald-200`) with `<CheckCircle />` icon.
- **Code Tokens**: Parses backticks (e.g., `` `SaveViewToSessionFile` ``) into monospace code badges.
- **Governance Warning Box**: Highlights human-in-the-loop authorization gates in a warm warning card.

---

## 5. Security & Multi-Tenant Access Control

1. **Role-Based Access Control (RBAC)**:
   - Only the **Globex Analyst persona** (`dev-other` or `globex-tenant`) is authorized to trigger blast radius simulations.
   - Non-Globex analysts (e.g. Acme tenant) receive an immediate fail-closed rejection:
     `"You do not have permission to execute this operation. Simulate Blast Radius is restricted exclusively to the Globex Analyst persona."`
2. **Context-Scoping & Anti-Enumeration 404s**:
   - If an incident ID is supplied, the system strictly validates tenant ownership. Cross-tenant incident probing returns a generic `not_found` error rather than a `403 Forbidden`, preventing identifier enumeration.
3. **Adversarial Input Sanitization**:
   - Query inputs are sanitized against SQL injection patterns, destructive shell meta-characters, and LLM role-override prompts.

---

## 6. Verification & Automated Testing

The implementation is verified via the test suite in [`tests/rbac.test.ts`](file:///D:/mario/mINTS/ShieldDesk/UpdatedMainBranch/SHIELD-DESK/tests/rbac.test.ts):

```bash
# Execute the full automated test suite (40 passing tests)
npm test

# Run TypeScript compiler static analysis
npx tsc --noEmit
```

### Verified Test Cases:
- `FR-1 / RBAC Gate`: Acme analyst blocked with `not_authorized`.
- `Priority 1`: Globex analyst executes `CVE-2024-6387` and receives 4 architectural layers, downstream dependencies, and posture delta.
- `Specialized Profiles`: Verified exact layer outputs for `CVE-2007-4475`.
- `Dynamic Heuristic`: Verified dynamic layer synthesis on arbitrary unknown CVEs (`CVE-2023-9999`).
- `Tenant Isolation`: Globex analyst querying Acme's `INC-1042` receives `not_found` anti-enumeration response.

---

## 7. Developer Quickstart / Example Interaction

### Request:
```text
Simulate Blast Radius for CVE-2007-4475
```

### Response:
```text
Simulated Blast Radius Assessment for **CVE-2007-4475**:

Target Asset & Scope: **SAPgui Client Endpoint (FIN-WS-042)**

1. **Initial Vector** [CRITICAL] — An attacker hosts a malicious web page targeting the `SaveViewToSessionFile` method in the ActiveX control. A user running an unpatched SAPgui accesses the link via Internet Explorer.

2. **Process Layer** [HIGH] — The buffer overflows on the stack. The attacker executes arbitrary binary code directly under the execution context of the hosting browser or application (`iexplore.exe` or `saplogon.exe`).

3. **Host System** [MEDIUM] — The payload inherits the **privilege level of the local desktop user**. If the employee runs as a Local Administrator, the attacker gains total control over the endpoint (registry, local data, credential dumping).

4. **Network Layer** [LOW-TO-MEDIUM] — Isolated to the workstation initially. The blast radius expands horizontally *only* if the compromised workstation holds active SAP session tokens or administrative network credentials to pivot to corporate SAP application servers.

Governance Note: Blast radius simulations are predictive models. Tier 2 host isolation requires human analyst authorization.
```
