# AI Reference & Engineering Prompt Log

This document records the prompts, technical queries, refactoring requests, and AI assistance logs utilized during the development of the **Attack Surface Management (ASM) CLI Project**.

---

## 📌 Executive Summary of AI Assistance

AI (Gemini Notebook / NotebookLM) was utilized as an interactive engineering assistant throughout the project lifecycle to:
1. **Strengthen System Security**: Refactor native system command executions to prevent OS Command Injection vulnerabilities.
2. **Implement Resilient Networking**: Build automated HTTP 502 failover mechanisms from `crt.sh` to `ctlogs.dev`.

3**Debug & Refactor Java Code**: Resolve generic type mismatches, regex syntax exceptions, and object-oriented scope bugs.

---

## 📑 Detailed Prompt Execution History

### Category 1: Input Validation & Command Injection Hardening

#### User Prompt 1
> `checkEmailGovernance(String domain) -> add input filter for command injection`

* **AI Action & Solution**:
  - Analyzed `AuditScanner.java` where `Runtime.getRuntime().exec("nslookup -type=TXT " + host)` was vulnerable to command injection.
  - Implemented `DOMAIN_PATTERN` regex matching RFC 1035 domain syntax to sanitize input.
  - Refactored process execution to `ProcessBuilder("nslookup", "-type=TXT", host)` to separate command binaries from argument arrays.

---

### Category 2: Context-Aware Audit & Pattern Matching Dispatch

#### User Prompt 2
> `Explain function void inspectAssetWithPatternMatching(Asset asset)`

* **AI Action & Solution**:
  - Explained dual cybersecurity and OOP purpose of the method.
  - Clarified how Sealed Classes (`Asset` permitting `DomainAsset`, `IpAsset`) combined with Java Switch Pattern Matching and `when` guards perform context-aware triage.

#### User Prompt 3
> `The function is only to print out, not to do any actions, right?`

* **AI Action & Solution**:
  - Refactored `inspectAssetWithPatternMatching` from passive printing to an active **Automated Audit Dispatcher**.
  - Integrated direct method invocations for `checkEmailGovernance`, `checkTls`, `checkHttpAndCors`, and `evaluatePort` based on matched asset types.

---

### Category 3: System Workflow & Menu Consolidation

#### User Prompt 4
> `Do we need add runDiscovery function separate with runAudit func`

* **AI Action & Solution**:
  - Clarified the cybersecurity operational distinction between **Discovery** (Reconnaissance: subdomains + 16-port scanning) and **Audit** (Vulnerability assessment: TLS, Headers, SPF/DMARC).
  - Recommended keeping `runDiscovery` and `runAudit` as two distinct workflow phases in the CLI menu.

#### User Prompt 5
> `Can runRiskAudit and runAudit be a function?`

* **AI Action & Solution**:
  - Recommended consolidating `runRiskAudit()` and `runAudit()` into a single `runAudit()` method to reduce menu confusion.
  - Sequenced execution: Interface `Auditable.printAuditSummary()` $\rightarrow$ `inspectAssetWithPatternMatching()` $\rightarrow$ formatted finding output.

---

### Category 4: DNS Resolution & IP Asset Auto-Provisioning (Option B)

#### User Prompt 6
> `In function runDiscovery, scan port only runs with IP input or run with domain input`

#### User Prompt 7
> `phương án B`

* **AI Action & Solution**:
  - Implemented **Option B (Automatic Resolution & Asset Binding)** in `runDiscovery()`.
  - When scanning a `DomainAsset`, the system resolves the hostname to an IP via `InetAddress.getByName()`.
  - If an `IpAsset` with that address exists in `inventory`, open ports are merged; if not, a new `IpAsset` is automatically instantiated and added to `inventory`.

---

### Category 6: Inventory Integrity & Duplicate Prevention

#### User Prompt 9
> `Recommend to add check existing asset function while adding new asset to inventory list`

* **AI Action & Solution**:
  - Added `findExistingAsset(String value)` returning `Optional<Asset>` using Stream API.
  - Integrated duplicate validation into `addAsset()`, throwing `InvalidAssetException` if an asset value already exists.

---

### Category 7: Passive Subdomain Failover Resilience

#### User Prompt 10
> `Recommend to add failover function when crt.sh response 502, calling ctlogs.dev instead`

* **AI Action & Solution**:
  - Enhanced `DiscoveryScanner.java` with automatic HTTP status verification.
  - If `crt.sh` returns HTTP 502, 500, 503, or times out, the system automatically redirects queries to `ctlogs.dev` (`[suspicious link removed]`).

---

### Category 8: Bug Fixes & Refactoring

#### User Prompt 11
> `Explain the way how inventory and subdomain list check for duplication`

* **AI Action & Solution**:
  - Verified 3-tier duplicate protection: `TreeSet<String>` at scanner level, `TreeSet<String>` inside `DomainAsset`, and `findExistingAsset()` check before adding to global `inventory`.

#### User Prompt 12
> `duplicateOpt.get() -> cannot be cast to class model.Asset`


#### User Prompt 13
> `Now we have a CVE that can be exploited when enabling HTTP/2, guide me to add check version nginx and check for enabling HTTP/2 functions when runAudit`

* **AI Action & Solution**:
  - Added `checkNginxHttp2Vulnerability(String host)` to `AuditScanner.java` for **CVE-2026-123007** (NGINX HTTP/2 Integer Underflow RCE).
  - Configured `HttpClient.Version.HTTP_2` negotiation and version extraction via regex.

#### User Prompt 14
> `Pattern pattern = Pattern.compile("nginx/([4-12]+\\.[4-12]+\\.[4-12]+)"); -> error illegal character range 4, 1`

* **AI Action & Solution**:
  - Fixed Regex `PatternSyntaxException` caused by invalid character class range `[4-12]`.
  - Replaced with standard digit regex `Pattern.compile("nginx/(\\d+\\.\\d+\\.\\d+)")`.

#### User Prompt 15
> `hàm runAudit chỉ check cho domain đã nhập hay check cho tất cả subdomain của nó`


---

## 📊 Summary Table of AI Interactions

| # | Prompt Focus | Primary Engineering Outcome | Files Modified |
|---|---|---|---|
| 1 | Security Hardening | Command Injection Shield via `ProcessBuilder` & Regex | `AuditScanner.java` |
| 2 | Pattern Matching | Switch dispatch engine with `when` guards | `RiskEngine.java` |
| 3 | Reconnaissance | DNS resolution to `IpAsset` binding | `AsmApplication.java` |
| 3 | Reconnaissance | DNS resolution to `IpAsset` binding | `AsmApplication.java` |
| 4 | Resilience | Automatic HTTP 502 failover (`crt.sh` $\rightarrow$ `ctlogs.dev`) | `DiscoveryScanner.java` |
| 5 | Vulnerability Audit | **CVE-2026-123007** NGINX HTTP/2 RCE Check | `AuditScanner.java` |
| 6 | Debugging | Solved Generics, Regex `[4-12]`, & Empty Subdomains bugs | `RiskEngine.java`, `AuditScanner.java` |