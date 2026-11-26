# Defensive Attack Surface Management (ASM) System

A robust, enterprise-grade Java 27 Command Line Interface (CLI) application designed for defensive cybersecurity posture management. The system automates digital asset inventory management, passive subdomain discovery, multi-threaded TCP port scanning, configuration auditing, CVE vulnerability scanning, and security assessment report generation.

---

## 🌟 Key Capabilities & Features

### 1. Functional Features
* **Asset Registration & Classification (F-001)**: Register and manage `DomainAsset`, `IpAsset`, and instances with environment tagging (`PROD`, `STAGING`, `DEV`) and exposure boundaries (`PUBLIC`, `INTERNAL`).
* **Aligned Inventory Table (F-002)**: Display assets in a clean, formatted CLI matrix with real-time risk scores and open port counters.
* **Passive Reconnaissance & Auto-Failover (F-003)**: Enumerate subdomains via `crt.sh` Certificate Transparency logs with automatic failover to `ctlogs.dev` upon HTTP 502/downtime.
* **Multi-Threaded Port Scanner & Option B Binding (F-003)**: Scan 16 critical TCP ports asynchronously (`ExecutorService`), grab service banners, resolve DNS to IP, and automatically instantiate/link `IpAsset` records in the inventory.
* **Contextual Audit Engine (F-004)**: Perform TLS certificate expiration checks, HTTP Security Headers analysis (HSTS, CSP, X-Frame-Options, CORS), DNS SPF/DMARC governance auditing, and real-time NGINX HTTP/2 RCE vulnerability checks (**CVE-2026-123007**).
* **Risk Dashboard & Export (F-005, F-006)**: Aggregate severity metrics (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and generate standalone audit reports (`asm_report.txt` and `ASM_Project_Report.docx`).

### 2. Java 25 / 27 Modern Features & OOP Mechanics
* **JEP 507 (Flexible Constructor Bodies)**: Perform parameter validation and domain normalization before calling `super(...)` in `DomainAsset`.
* **JEP 532 (Primitive Patterns in Switch)**: Evaluate primitive `int` port numbers directly inside pattern matching `switch` expressions with guarded `when` clauses in `RiskEngine.java`.
* **Sealed Class Hierarchy**: `public abstract sealed class Asset permits DomainAsset, IpAsset, CloudAsset`.
* **Pattern Matching for Switch**: Exhaustive type pattern matching with guard clauses (`case DomainAsset d when d.getAssetCategory().equals("APEX_DOMAIN")`).
* **Defensive Copying & Immutability**: Immutable `OwnerContact` with copy constructors and `Collections.unmodifiableList` / `Collections.unmodifiableMap` getters.
* **Java Records**: Concise, immutable data transfer via `public record RiskFinding(...)`.
* **Interface Design**: `Auditable` interface featuring abstract, `default`, `static`, and `private` helper methods.

---

## 🛠️ Architecture & Package Structure

```text
src/
└── com/
    └── asm/
        ├── AsmApplication.java           # CLI Entrypoint & File Persistence
        ├── core/
        │   └── Auditable.java            # Interface with Default/Static/Private methods
        ├── engine/
        │   └── RiskEngine.java           # Java 27 Switch Pattern Matching Engine
        ├── exception/
        │   ├── AssetNotFoundException.java # Runtime Unchecked Exception
        │   └── InvalidAssetException.java  # Checked Exception
        ├── model/
        │   ├── Asset.java                # Sealed Parent Class
        │   ├── AssetFilters.java         # Functional Predicates & Varargs
        │   ├── CloudAsset.java           # Cloud Account Record Model
        │   ├── DomainAsset.java          # Apex & Subdomain Model (JEP 507)
        │   ├── Environment.java          # Environment Enum (PROD, STAGING, DEV)
        │   ├── Exposure.java             # Exposure Enum (PUBLIC, INTERNAL)
        │   ├── IpAsset.java              # Host & Port Binding Model
        │   ├── NetworkEntity.java        # Base Entity Class
        │   ├── OwnerContact.java         # Immutable Class with Defensive Copying
        │   ├── RiskFinding.java          # Java Record Model
        │   └── Severity.java             # Risk Severity Enum with Weights
        └── scanner/
            ├── AuditScanner.java         # TLS, HTTP Headers, SPF/DMARC, CVE Scanner
            └── DiscoveryScanner.java     # crt.sh / ctlogs.dev Failover & Multi-Threaded Scanner
```

---

## 🚀 Compilation & Running Instructions

### Requirements
* **JDK 27** (or JDK 25+ with preview features enabled)
* Standard Terminal / Command Prompt

### Build and Run Commands

```bash
# 1. Compile all Java source files with preview features enabled
javac --enable-preview --release 27 -d bin $(find src -name "*.java")

# 2. Execute the CLI application
java --enable-preview -cp bin com.asm.AsmApplication
```

---

