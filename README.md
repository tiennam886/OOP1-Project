# Attack Surface Management (ASM) CLI Tool

**Attack Surface Management (ASM)** is a production-grade, multi-threaded Java 27 CLI application designed to help DevSecOps and security engineering teams catalog public-facing digital infrastructure, perform passive subdomain discovery, scan service ports, evaluate security compliance, and group organizational assets into hierarchical risk clusters.

This project serves as a comprehensive benchmark for **Object-Oriented Programming (OOP)** principles, advanced Java design patterns, and cutting-edge features introduced in modern JDK releases, including **Sealed Classes**, **Pattern Matching Switch**, **Flexible Constructor Bodies (JEP 507)**, and **Primitive Patterns in Switch (JEP 532)**.

---

## Key Features

### 1. Asset Cataloging & Inventory Management
* **Multi-Category Asset Support**: Register and track `DomainAsset` (Apex Domains & Subdomains), `IpAsset` (IPv4 Hosts).
* **Rich Metadata Attributes**: Tag assets with `Environment` (`PRODUCTION`, `STAGING`, `DEVELOPMENT`), `Exposure` (`PUBLIC`, `INTERNAL`, `VPC_ONLY`), and `OwnerContact` (`TeamName`, `Email`).

### 2. Passive Reconnaissance & Failover Architecture
* **Certificate Transparency Logs Querying**: Queries CT logs (`crt.sh`) to extract public subdomains passively without triggering active network alerts.
* **Automatic REST API Failover**: Built-in fallback mechanism that automatically redirects queries to `ctlogs.dev` REST API if primary endpoints experience an HTTP 502 gateway error or timeout.

### 3. Multi-Threaded Asynchronous Port Scanning
* **ExecutorService Thread Pool**: Concurrently scans 16 common service ports (21 FTP, 22 SSH, 80 HTTP, 443 HTTPS, 3306 MySQL, 5432 PostgreSQL, 6379 Redis, etc.).
* **Banner Grabbing & Service Detection**: Captures network banners and automatically binds discovered IPv4 hosts (`IpAsset`) to their parent Apex Domain.

### 4. Contextual Vulnerability Audit Engine
* **TLS/SSL Expiry & Certificate Audit**: Validates certificate validity periods and issuer health.
* **HTTP Security Headers Inspection**: Checks for missing `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, and permissive `CORS` origins.
* **Email Governance Analysis**: Verifies DNS `SPF` and `DMARC` records to prevent email domain spoofing.
* **Vulnerability Assessment**: Actively checks for high-severity vulnerability advisories and security posture risks.

### 5. Hierarchical Risk Dashboard & Clustering
* **Severity Breakdown**: Categorizes risk findings into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
* **Apex Domain Cluster View**: Groups risks hierarchically: `Apex Domain` -> `Associated IP & Open Ports` -> `Related Subdomains`.

### 6. Dynamic Multi-Criteria Asset Filtering
* Filter inventory by **Environment** (`PROD`), **Exposure** (`PUBLIC`), **Risk Score** (`Score > 5`), **Apex Domain Cluster** (including IP & Subdomains), or **Owner Contact**.

### 7. Asset Metadata Editing & State Reuse
* Live modification of `Environment`, `Exposure`, and `OwnerContact` metadata.
* Caches discovered subdomains and IP bindings directly inside `DomainAsset` state to avoid redundant network overhead.

### 8. Audit Report Export & Persistence
* Exports formatted text audit reports (`asm_report_*.txt`) and maintains immutable historical `AssetSnapshot` records.

---
## Package Structure

```
com.asm/
├── app/
│   └── AttackSurfaceManager.java     # CLI User Interface & Application Main Entry Point
├── engine/
│   └── RiskEngine.java                # Vulnerability Evaluation & Pattern Matching Switch Engine
├── scanner/
│   ├── Auditable.java                 # Security Audit Interface Contract
│   ├── AuditScanner.java              # TLS, HTTP Header, SPF & CVE Assessment Implementation
│   └── DiscoveryScanner.java          # CT Log Reconnaissance & Multi-Threaded Port Scanner
├── util/
│   └── AssetFilters.java              # Functional Predicates & Multi-Criteria Filtering Tools
├── model/
│   ├── NetworkEntity.java             # Base Abstract Class (Value & Registration Date)
│   ├── Asset.java                     # Abstract Sealed Base Class (ID, Env, Exposure, Owner)
│   ├── DomainAsset.java               # Final Sealed Subclass for Domains & Subdomains
│   ├── IpAsset.java                   # Final Sealed Subclass for IPv4 Addresses & Ports
│   ├── CloudAsset.java                # Final Sealed Subclass for Cloud Resources
│   ├── Environment.java               # Enum (PRODUCTION, STAGING, DEVELOPMENT)
│   ├── Exposure.java                  # Enum (PUBLIC, INTERNAL, VPC_ONLY)
│   ├── Severity.java                  # Enum with Weighted Risk Scores (CRITICAL, HIGH, etc.)
│   ├── OwnerContact.java              # Custom Immutable Class with Defensive Copying
│   ├── RiskFinding.java               # Java Record for Security Findings
│   ├── AssetSnapshot.java             # Java Record for Historical State Snapshots
│   ├── InvalidAssetException.java     # Custom Checked Exception
│   └── AssetNotFoundException.java    # Custom Unchecked Exception
```

---
## Java Knowledge & Language Features Implemented

### 1. Core Object-Oriented Fundamentals
* **Inheritance & Abstraction**: `NetworkEntity` -> `Asset` -> `DomainAsset` / `IpAsset`.
* **Encapsulation**: Private fields protected with defensive getters and setters.
* **Polymorphism**: Dynamic dispatch on `calculateRiskScore()` across domain and IP asset types.
* **Method Overloading**: Overloaded `addFinding()` in `Asset.java`.
* **Varargs & LVTI**: `AssetFilters.byEnvironment(Environment... envs)` and `var` type inference in CLI handlers.
* **Exception Handling**: Checked `InvalidAssetException` vs Unchecked `AssetNotFoundException`.

### 2. Advanced Java Features
* **Defensive Copying**: Implemented in `OwnerContact`, `getSubdomains()`, `getOpenPorts()`, and `getFindings()`.
* **Custom Immutable Types**: `OwnerContact` uses `private final` fields and a copy constructor `public OwnerContact(OwnerContact other)`.
* **Sealed Classes (`sealed` / `permits`)**: `public abstract sealed class Asset permits DomainAsset, IpAsset, CloudAsset`.
* **Java Records**: `RiskFinding(Severity severity, String category, String message)` and `AssetSnapshot`.
* **Interface Default, Static & Private Methods**: Clean interface design in `Auditable.java`.
* **Lambdas & Functional Predicates**: Reusable stream filtering via `Predicate<Asset>` in `AssetFilters.java`.

### 3. Modern JDK 25 / JDK 27 Features
* **Flexible Constructor Bodies (JEP 507)**: Pre-processing domain normalization and date calculations **before** invoking `super(...)` in `DomainAsset.java`:
  ```java
  public DomainAsset(String id, String domainName, Environment env, Exposure exp, OwnerContact owner) {
      LocalDate now = LocalDate.now();
      String normalizedDomain = (domainName != null) ? domainName.trim().toLowerCase() : "unknown.local";
      super(id, normalizedDomain, env, exp, owner, now); // Statements allowed BEFORE super()
      this.isApex = !normalizedDomain.startsWith("www.") && normalizedDomain.split("\.").length == 2;
  }
  ```
* **Pattern Matching Switch with Guarded Clauses (`when`)**: Direct pattern matching on asset types in `RiskEngine.java`:
  ```java
  switch (asset) {
      case DomainAsset d when "APEX_DOMAIN".equalsIgnoreCase(d.getAssetCategory()) -> auditApexDomain(d);
      case DomainAsset d -> auditSubdomain(d);
      case IpAsset ip when ip.getOpenPorts().size() > 5 -> alertHighRiskIp(ip);
      case IpAsset ip -> auditIpPorts(ip);
      case null, default -> System.out.println("[-] Unrecognized asset type.");
  }
  ```
* **Primitive Patterns in Switch (JEP 532)**: Switch pattern matching directly on primitive `int port` values:
  ```java
  return switch (port) {
      case 21, 23 -> List.of(new RiskFinding(Severity.HIGH, "PORT_SCAN", "Cleartext service port " + port));
      case int p when (p == 3306 || p == 5432 || p == 6379) -> List.of(new RiskFinding(Severity.HIGH, "DATABASE", "Database port " + p + " exposed!"));
      default -> List.of(new RiskFinding(Severity.LOW, "PORT_SCAN", "Open port " + port));
  };
  ```

---
## Getting Started

### Compilation & Running

```bash
# 1. Compile all Java source files with Preview Features enabled
javac --enable-preview --release 27 -d bin $(find src -name "*.java")

# 2. Run the application CLI
java --enable-preview -cp bin com.asm.app.AttackSurfaceManager
```

---

## Interactive CLI Navigation Guide

```text
=======================================================
    DEFENSIVE ATTACK SURFACE MANAGEMENT (ASM) CLI
=======================================================
1. Add a New Asset (Domain, IP, Cloud Account)
2. Show List of Assets
3. Filter Assets (PROD, PUBLIC, Score, Apex Cluster, Owner)
4. Edit Asset Metadata (Environment, Exposure, Owner)
5. Run Discovery Scanner (Subdomains & Port Scan)
6. Run Security Audit Engine (TLS, Headers, CVEs)
7. Show Executive Risk Dashboard (Hierarchical Clusters)
8. Export Risk Audit Report (Text File)
9. Remove an Asset (Save Historical Snapshot)
10. View Deleted Asset Snapshots History
0. Exit & Save Inventory
=======================================================
```
