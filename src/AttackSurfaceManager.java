import core.AssetFilters;
import engine.RiskEngine;
import model.*;
import exception.*;
import scanner.AuditScanner;
import scanner.DiscoveryScanner;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class AttackSurfaceManager {
    private static final String DATA_FILE = "assets.txt";
    private static final List<Asset> inventory = new ArrayList<>();
    private static final List<AssetSnapshot> snapshots = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);
    private static final RiskEngine riskEngine = new RiskEngine();
    private final DiscoveryScanner discoveryScanner = new DiscoveryScanner();
    private static final AuditScanner auditScanner = new AuditScanner();
    private static int idSequence = 100;

    static void main() {
        var app = new AttackSurfaceManager();
        app.run();
    }

    private void seedSampleData() {
        var owner = new OwnerContact("RedTeam-Ops", "red@company.com");
        var d1 = new DomainAsset("A-" + (++idSequence), "corp-portal.com", Environment.PROD, Exposure.PUBLIC, owner);
        d1.addSubdomain("prod");
        d1.addSubdomain("dev");
        d1.addFinding(Severity.HIGH, "TLS", "TLS Certification will be expired within 7 days");

        var ip1 = new IpAsset("A-" + (++idSequence), "198.51.100.25", Environment.DEV, Exposure.PUBLIC, owner, "/32");
        ip1.addOpenPort(3306, "MySQL 8.0-unpatched");
        ip1.addOpenPort(22, "OpenSSH 7.4");
        ip1.addFinding(Severity.CRITICAL, "DATABASE", "MySQL port 3306 is exposed via public Internet!");

        inventory.add(d1);
        inventory.add(ip1);
    }

    public void run() {
        loadFromFile();
        boolean isRunning = true;
        while (isRunning) {
            String menuBuilder = """
                    
                    =======================================================
                        DEFENSIVE ATTACK SURFACE MANAGEMENT (ASM) CLI
                    =======================================================
                    1. Add a New Asset (Domain, IP, Cloud Account)
                    2. Show List of Assets\s
                    3. Filter Assets by Risk
                    4. Edit Asset's Metadata
                    5. Run Discovery Asset
                    6. Run Risk Evaluation
                    7. Show Risk Dashboard
                    8. Export Risk Report
                    9. Remove an Asset
                    10. Show Snapshots History
                    0. Exit
                    Choose an option (0-10):\s""";
            System.out.print(menuBuilder);

            var choice = scanner.nextLine().trim();

            if ("0".equals(choice)) {
                System.out.println("[*] Saved data to TXT file . Goodbye!");
                break;
            }

            switch (choice) {
                case "1" -> addAsset();
                case "2" -> listAssets();
                case "3" -> filterAssets();
                case "4" -> editAssetMetadata();
                case "5" -> runDiscovery();
                case "6" -> runRiskAudit();
                case "7" -> showRiskDashboard();
                case "8" -> exportReport();
                case "9" -> deleteAsset();
                case "10" -> displaySnapshots();
                default -> IO.println("[-] Invalid Option");
            }
            if (!askToContinueOrExit()) {
                saveToFile();
                System.out.println("[*] Save data and close application. Good bye!!");
                isRunning = false;
            }
        }
        scanner.close();
    }

    private static void addAsset() {
        try {
            System.out.print("Choose an Asset Type (1: DOMAIN, 2: IP): ");
            var typeChoice = scanner.nextLine().trim();

            System.out.print("Input Asset's Value (EX: example.com, 1.1.1.1): ");
            var val = scanner.nextLine().trim();
            if (val.isEmpty()) throw new InvalidAssetException("Asset's value can not be empty!");
            var duplicateOpt = findExistingAsset(val);
            if (duplicateOpt.isPresent()) {
                Asset existing = duplicateOpt.get();
                throw new InvalidAssetException(String.format(
                        "[-] Duplicate asset rejected! '%s' is already registered as [%s] with Category: %s.",
                        val, existing.getId(), existing.getAssetCategory()
                ));
            }
            System.out.print("Environment (1: PROD, 2: STAGING, 3: DEV): ");
            var env = switch (scanner.nextLine().trim()) {
                case "1" -> Environment.PROD;
                case "2" -> Environment.STAGING;
                default -> Environment.DEV;
            };

            System.out.print("Exposure Perimeter (1: PUBLIC, 2: INTERNAL): ");
            var exp = "2".equals(scanner.nextLine().trim()) ? Exposure.INTERNAL : Exposure.PUBLIC;

            System.out.print("Contact of Owner: ");
            System.out.print("Enter Owner Name/Team [Default: DevSecOps]: ");
            var ownerName = scanner.nextLine().trim();
            if (ownerName.isBlank()) ownerName = "DevSecOps";

            System.out.print("Enter Owner Email [Default: " + ownerName.toLowerCase().replaceAll("\\s+", "") + "@company.com]: ");
            var ownerEmail = scanner.nextLine().trim();
            if (ownerEmail.isBlank()) {
                ownerEmail = ownerName.toLowerCase().replaceAll("\\s+", "") + "@company.com";
            }
            var owner = new OwnerContact(ownerName, ownerEmail);

            var newId = "A-" + (++idSequence);
            Asset newAsset = switch (typeChoice) {
                case "1" -> new DomainAsset(newId, val, env, exp, owner);
                case "2" -> new IpAsset(newId, val, env, exp, owner, "/32");
                default -> throw new InvalidAssetException("Invalid Asset's Type: " + typeChoice);
            };

            inventory.add(newAsset);
            System.out.println("[+] Successfully add the new asset: " + newAsset);
        } catch (InvalidAssetException e) {
            System.out.println("[-] Invalid Asset: " + e.getMessage());
        }
    }

    private static void listAssets() {
        if (inventory.isEmpty()) {
            System.out.println("[-] No Asset recorded.");
            return;
        }
        System.out.printf("\n%-4s %-8s %-28s %-14s %-8s %-9s %-22s %-6s %-6s%n",
                "NO", "ID", "VALUE", "TYPE", "ENV", "EXPOSURE", "OWNER", "PORTS", "RISKS");

        System.out.println("-".repeat(110));

        for (int i = 0; i < inventory.size(); i++) {
            Asset a = inventory.get(i);

            int portCount = (a instanceof IpAsset ip) ? ip.getOpenPorts().size() : 0;

            String ownerInfo = a.getOwner().getTeamName();
            if (ownerInfo.length() > 20) {
                ownerInfo = ownerInfo.substring(0, 17) + "...";
            }


            String displayValue = a.getValue();
            if (displayValue.length() > 26) {
                displayValue = displayValue.substring(0, 23) + "...";
            }

            System.out.printf("%-4d %-8s %-28s %-14s %-8s %-9s %-22s %-6d %-6d%n",
                    (i + 1),
                    a.getId(),
                    displayValue,
                    a.getAssetCategory(),
                    a.getEnvironment(),
                    a.getExposure(),
                    ownerInfo,
                    portCount,
                    a.getFindings().size()
            );
        }
        System.out.println("-".repeat(110));
    }

    private static void filterAssets() {
        System.out.println("\n--- FILTER ASSETS INVENTORY ---");
        System.out.println("1: Only PROD Environment");
        System.out.println("2: Only PUBLIC Exposed");
        System.out.println("3: Risk Score > 5");
        System.out.println("4: By Apex Domain Cluster (Apex Domain + Associated IP + Subdomains)");
        System.out.println("5: By Owner Contact (Name / Email / Department)");
        System.out.print("Choose Filter Option (1-5): ");

        var fChoice = scanner.nextLine().trim();
        final int minThreshold = 5;

        List<Asset> filtered = switch (fChoice) {
            case "1" -> inventory.stream()
                    .filter(AssetFilters.byEnvironment(Environment.PROD))
                    .toList();

            case "2" -> inventory.stream()
                    .filter(AssetFilters.isPublicExposed())
                    .toList();

            case "3" -> inventory.stream()
                    .filter(AssetFilters.riskScoreAbove(minThreshold))
                    .toList();

            case "4" -> {
                System.out.print("Enter Target Apex Domain (e.g., corp-portal.com): ");
                var apexInput = scanner.nextLine().trim();
                yield AssetFilters.filterByApexDomainCluster(inventory, apexInput);
            }

            case "5" -> {
                System.out.print("Enter Owner Name, Email, or Department to search: ");
                var ownerQuery = scanner.nextLine().trim();
                yield AssetFilters.filterByOwner(inventory, ownerQuery);
            }

            default -> inventory;
        };

        if (filtered.isEmpty()) {
            System.out.println("[-] Not Found suitable asset matching criteria.");
            return;
        }

        System.out.printf("%n[+] FILTER RESULT (%d MATCHED ASSETS):%n", filtered.size());
        System.out.printf("%-4s %-8s %-28s %-14s %-8s %-9s %-10s %-20s%n",
                "NO", "ID", "VALUE", "TYPE", "ENV", "EXPOSURE", "SCORE", "OWNER");
        System.out.println("-".repeat(110));

        for (int i = 0; i < filtered.size(); i++) {
            Asset a = filtered.get(i);
            String ownerInfo = (a.getOwner() != null) ? a.getOwner().toString() : "N/A";

            System.out.printf("%-4d %-8s %-28s %-14s %-8s %-9s %-10d %-20s%n",
                    (i + 1),
                    a.getId(),
                    a.getValue(),
                    a.getAssetCategory(),
                    a.getEnvironment(),
                    a.getExposure(),
                    a.calculateRiskScore(),
                    ownerInfo
            );
        }
        System.out.println("-".repeat(110));
    }

    private void editAssetMetadata() {
        listAssets();
        System.out.print("Enter Target Asset ID to update metadata (e.g., A-101): ");
        String assetId = scanner.nextLine().trim();

        Asset target = inventory.stream()
                .filter(a -> a.getId().equalsIgnoreCase(assetId))
                .findFirst()
                .orElse(null);

        if (target == null) {
            System.out.println("[-] Asset not found in inventory.");
            return;
        }

        System.out.printf("%n[*] Editing Metadata for Asset [%s] (%s)%n", target.getId(), target.getValue());
        System.out.println("  1. Update Environment (PRODUCTION, STAGING, DEVELOPMENT)");
        System.out.println("  2. Update Exposure (PUBLIC, INTERNAL, VPC_ONLY)");
        System.out.println("  3. Update Owner Contact (Name, Email, Department)");
        System.out.print("Select field to update (1-3): ");

        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1" -> {
                System.out.print("Enter new Environment (PROD/STAGE/DEV): ");
                String envInput = scanner.nextLine().trim().toUpperCase();
                try {
                    Environment newEnv = switch (envInput) {
                        case "PROD", "PRODUCTION" -> Environment.PROD;
                        case "STAGE", "STAGING" -> Environment.STAGING;
                        case "DEV", "DEVELOPMENT" -> Environment.DEV;
                        default -> Environment.UNKNOWN;
                    };
                    target.setEnvironment(newEnv);
                    System.out.println("[+] Environment updated successfully to: " + newEnv);
                } catch (Exception e) {
                    System.out.println("[-] Invalid Environment selection.");
                }
            }
            case "2" -> {
                System.out.print("Enter new Exposure (PUBLIC/INTERNAL): ");
                String expInput = scanner.nextLine().trim().toUpperCase();
                try {
                    Exposure newExp = switch (expInput) {
                        case "PUBLIC" -> Exposure.PUBLIC;
                        case "VPC", "VPC_ONLY" -> Exposure.VPC_ONLY;
                        default -> Exposure.INTERNAL;
                    };
                    target.setExposure(newExp);
                    System.out.println("[+] Exposure updated successfully to: " + newExp);
                } catch (Exception e) {
                    System.out.println("[-] Invalid Exposure selection.");
                }
            }
            case "3" -> {
                System.out.print("Enter Owner Name: ");
                String name = scanner.nextLine().trim();
                System.out.print("Enter Owner Email: ");
                String email = scanner.nextLine().trim();

                OwnerContact newOwner = new OwnerContact(
                        name.isBlank() ? target.getOwner().getTeamName() : name,
                        email.isBlank() ? target.getOwner().getEmail() : email
                );
                target.setOwner(newOwner);
                System.out.println("[+] Owner Contact updated successfully!");
            }
            default -> System.out.println("[-] Invalid choice. Aborting edit.");
        }
    }

    private void runDiscovery() {
        listAssets();
        System.out.print("Enter Target Asset ID for discovery (e.g., A-101): ");
        var targetId = scanner.nextLine().trim();

        var target = inventory.stream()
                .filter(a -> a.getId().equalsIgnoreCase(targetId))
                .findFirst()
                .orElse(null);

        if (target == null) {
            System.out.println("[-] Asset not found with ID: " + targetId);
            return;
        }

        System.out.println("\n[*] Initiating reconnaissance pipeline for: " + target.getValue());

        if (target instanceof DomainAsset domainAsset) {
            System.out.println("[*] Querying crt.sh certificate logs for " + domainAsset.getValue() + "...");
            Set<String> subs = discoveryScanner.discoverSubdomains(domainAsset.getValue());

            if (subs.isEmpty()) {
                System.out.println("[-] No subdomains discovered in public CT logs.");
            } else {
                System.out.printf("[+] Discovered %d subdomains for %s:%n", subs.size(), domainAsset.getValue());
                int addedCount = 0;
                for (String sub : subs) {
                    domainAsset.addSubdomain(sub);
                    domainAsset.setLastScanned(Instant.now());
                    if (findExistingAsset(sub).isEmpty()) {
                        var newSubId = "A-" + (++idSequence);
                        inventory.add(new DomainAsset(newSubId, sub, domainAsset.getEnvironment(),
                                domainAsset.getExposure(), domainAsset.getOwner()));
                        addedCount++;
                    }
                }
                System.out.printf("[+] Successfully added %d new child subdomains into inventory.%n", addedCount);
            }
        }

        System.out.println("[*] Launching multi-threaded port scan across 16 critical network ports...");
        Map<Integer, String> openPorts = discoveryScanner.scanPorts(target.getValue(), DiscoveryScanner.DEFAULT_PORTS);

        if (openPorts.isEmpty()) {
            System.out.println("[-] No responsive open ports identified within scanned scope.");
            return;
        }

        System.out.printf("[+] Identified %d open ports on %s:%n", openPorts.size(), target.getValue());
        openPorts.forEach((p, banner) -> System.out.printf("  -> Port %-5d | Banner: %s%n", p, banner));

        if (target instanceof IpAsset ip) {
            openPorts.forEach(ip::addOpenPort);
            System.out.println("[+] Updated open ports directly to selected IpAsset.");
        } else if (target instanceof DomainAsset domain) {
            try {
                String resolvedIpStr = InetAddress.getByName(domain.getValue()).getHostAddress();
                System.out.println("[*] DNS Resolution successful: " + domain.getValue() + " -> " + resolvedIpStr);

                var existingIpOpt = findExistingAsset(resolvedIpStr);
                if (existingIpOpt.isPresent() && existingIpOpt.get() instanceof IpAsset existingIp) {
                    openPorts.forEach(existingIp::addOpenPort);
                    domain.setAssociatedIp(resolvedIpStr);
                    domain.setLastScanned(Instant.now());
                    System.out.printf("[+] Merged %d open ports into existing host [%s].%n",
                            openPorts.size(), existingIp.getId());
                } else {
                    var newIpId = "A-" + (++idSequence);
                    var newIpAsset = new IpAsset(newIpId, resolvedIpStr, domain.getEnvironment(),
                            domain.getExposure(), domain.getOwner(), "/32");
                    openPorts.forEach(newIpAsset::addOpenPort);
                    domain.setAssociatedIp(resolvedIpStr);
                    domain.setLastScanned(Instant.now());
                    inventory.add(newIpAsset);
                }
            } catch (UnknownHostException e) {
                System.out.println("[-] Could not resolve domain to an IP address: " + domain.getValue());
            }
        }
    }

    private void showRiskDashboard() {
        System.out.println("\n==========================================================================================");
        System.out.println("                         EXECUTIVE RISK DASHBOARD & CLUSTER METRICS                       ");
        System.out.println("==========================================================================================");
        System.out.println("1. View Full Infrastructure Dashboard");
        System.out.println("2. Filter Dashboard by Apex Domain Cluster");
        System.out.println("3. Filter Dashboard by Owner Contact");
        System.out.print("Select view option (1-3): ");

        String opt = scanner.nextLine().trim();
        List<Asset> activeScope = inventory;

        if ("2".equals(opt)) {
            System.out.print("Enter Apex Domain (e.g., corp-portal.com): ");
            String domain = scanner.nextLine().trim();
            activeScope = AssetFilters.filterByApexDomainCluster(inventory, domain);
        } else if ("3".equals(opt)) {
            System.out.print("Enter Owner Name/Email query: ");
            String q = scanner.nextLine().trim();
            activeScope = AssetFilters.filterByOwner(inventory, q);
        }

        if (activeScope.isEmpty()) {
            System.out.println("[!] No matching assets found for Dashboard rendering.");
            return;
        }

        Map<Severity, Long> severityCounts = activeScope.stream()
                .flatMap(a -> a.getFindings().stream())
                .collect(Collectors.groupingBy(RiskFinding::severity, Collectors.counting()));

        long criticals = severityCounts.getOrDefault(Severity.CRITICAL, 0L);
        long highs     = severityCounts.getOrDefault(Severity.HIGH, 0L);
        long mediums   = severityCounts.getOrDefault(Severity.MEDIUM, 0L);
        long lows      = severityCounts.getOrDefault(Severity.LOW, 0L);
        long infos     = severityCounts.getOrDefault(Severity.INFO, 0L);

        System.out.printf("%n  [SCOPE METRICS] Assets in Scope: %d | Total Active Findings: %d%n",
                activeScope.size(), activeScope.stream().mapToLong(a -> a.getFindings().size()).sum());
        System.out.printf("  [SEVERITY BREAKDOWN] CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d | INFO: %d%n",
                criticals, highs, mediums, lows, infos);
        System.out.println("------------------------------------------------------------------------------------------");

        List<DomainAsset> apexDomains = activeScope.stream()
                .filter(a -> a instanceof DomainAsset)
                .map(a -> (DomainAsset) a)
                .filter(d -> "APEX_DOMAIN".equalsIgnoreCase(d.getAssetCategory()))
                .toList();

        if (apexDomains.isEmpty()) {
            System.out.println("[*] No Apex Domains found in the selected scope.");
            return;
        }

        for (DomainAsset apex : apexDomains) {
            String scanTimeStr = (apex.getLastScanned() != null) ? apex.getLastScanned().toString() : "Never Scanned";
            String ownerStr = (apex.getOwner() != null) ? apex.getOwner().toString() + ")" : "Unassigned";

            System.out.printf("%n APEX DOMAIN CLUSTER: [%s] (ID: %s | Env: %s | Owner: %s)%n",
                    apex.getValue(), apex.getId(), apex.getEnvironment(), ownerStr);
            System.out.printf("   Last Audit Timestamp: %s%n", scanTimeStr);

            String assocIp = apex.getAssociatedIp();
            IpAsset matchingIpAsset = null;

            if (assocIp != null && !assocIp.isBlank()) {
                System.out.printf("   ├── Associated IP: %s%n", assocIp);

                matchingIpAsset = inventory.stream()
                        .filter(a -> a instanceof IpAsset)
                        .map(a -> (IpAsset) a)
                        .filter(ip -> ip.getValue().equalsIgnoreCase(assocIp))
                        .findFirst()
                        .orElse(null);

                if (matchingIpAsset != null && !matchingIpAsset.getOpenPorts().isEmpty()) {
                    System.out.printf("   │    └── Open Service Ports: %s%n", matchingIpAsset.getOpenPorts());
                }
            } else {
                System.out.println("   ├── Associated IP: Unresolved (Tip: Run Option 3 Discovery first)");
            }

            Set<String> subdomains = apex.getSubdomains();
            System.out.printf("   └── Related Subdomains (%d total): %s%n",
                    subdomains.size(), subdomains.isEmpty() ? "None" : String.join(", ", subdomains));

            List<RiskFinding> clusterFindings = new ArrayList<>(apex.getFindings());
            if (matchingIpAsset != null) {
                for (RiskFinding ipFinding : matchingIpAsset.getFindings()) {
                    if (!clusterFindings.contains(ipFinding)) {
                        clusterFindings.add(ipFinding);
                    }
                }
            }

            System.out.println("\n   --- Cluster Risk Findings ---");
            if (clusterFindings.isEmpty()) {
                System.out.println("   [+] Clean posture. No active vulnerabilities detected.");
            } else {
                clusterFindings.forEach(f -> System.out.printf("   -> [%-8s] (%-14s) %s%n",
                        f.severity(), f.category(), f.message()));
            }
            System.out.println("------------------------------------------------------------------------------------------");
        }
    }

    private void exportReport() {
        System.out.println("\n--- EXPORT RISK REPORT ---");
        System.out.println("1. Export Full System Audit Report");
        System.out.println("2. Export Report filtered by Apex Domain Cluster");
        System.out.println("3. Export Report filtered by Owner Contact");
        System.out.print("Select export mode (1-3): ");

        String choice = scanner.nextLine().trim();
        List<Asset> exportScope = inventory;
        String filterLabel = "ALL_ASSETS";

        if ("2".equals(choice)) {
            System.out.print("Enter Apex Domain (e.g., corp-portal.com): ");
            String domain = scanner.nextLine().trim();
            exportScope = AssetFilters.filterByApexDomainCluster(inventory, domain);
            filterLabel = "APEX_CLUSTER_" + domain;
        } else if ("3".equals(choice)) {
            System.out.print("Enter Owner query: ");
            String q = scanner.nextLine().trim();
            exportScope = AssetFilters.filterByOwner(inventory, q);
            filterLabel = "OWNER_" + q;
        }

        if (exportScope.isEmpty()) {
            System.out.println("[!] No matching assets found in the selected scope to export.");
            return;
        }

        String filename = "ASM_REPORT_" + filterLabel.replaceAll("[^a-zA-Z0-9_]", "_") + ".txt";

        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            out.println("===============================================================================");
            out.println("               DEFENSIVE ATTACK SURFACE MANAGEMENT (ASM) REPORT                ");
            out.println("===============================================================================");
            out.println("Generated At   : " + Instant.now());
            out.println("Filter Scope   : " + filterLabel);
            out.println("Scope Assets   : " + exportScope.size());
            out.println("===============================================================================\n");
            out.println("1. DOMAIN INFRASTRUCTURE & APEX CLUSTERS");
            out.println("-------------------------------------------------------------------------------");

            List<DomainAsset> apexDomains = exportScope.stream()
                    .filter(a -> a instanceof DomainAsset)
                    .map(a -> (DomainAsset) a)
                    .filter(d -> "APEX_DOMAIN".equalsIgnoreCase(d.getAssetCategory()))
                    .toList();

            if (apexDomains.isEmpty()) {
                out.println("No Apex Domains found in this export scope.");
            } else {
                for (DomainAsset apex : apexDomains) {
                    String ownerStr = (apex.getOwner() != null)
                            ? apex.getOwner().toString() + ")"
                            : "Unassigned";

                    out.printf("APEX DOMAIN  : %s [ID: %s]%n", apex.getValue(), apex.getId());
                    out.printf("  Environment  : %s | Exposure: %s | Owner: %s%n",
                            apex.getEnvironment(), apex.getExposure(), ownerStr);
                    out.printf("  Last Scanned : %s%n", apex.getLastScanned() != null ? apex.getLastScanned() : "Never");

                    String assocIp = apex.getAssociatedIp();
                    IpAsset matchingIpAsset = null;

                    if (assocIp != null && !assocIp.isBlank()) {
                        out.printf("  Associated IP: %s%n", assocIp);

                        matchingIpAsset = inventory.stream()
                                .filter(a -> a instanceof IpAsset)
                                .map(a -> (IpAsset) a)
                                .filter(ip -> ip.getValue().equalsIgnoreCase(assocIp))
                                .findFirst()
                                .orElse(null);

                        if (matchingIpAsset != null && !matchingIpAsset.getOpenPorts().isEmpty()) {
                            out.printf("    └── Open Service Ports: %s%n", matchingIpAsset.getOpenPorts());
                        }
                    } else {
                        out.println("  Associated IP: Unresolved (Tip: Run Option 3 Discovery first)");
                    }

                    out.printf("  Subdomains (%d): %s%n", apex.getSubdomains().size(),
                            apex.getSubdomains().isEmpty() ? "None" : String.join(", ", apex.getSubdomains()));

                    List<RiskFinding> clusterFindings = new ArrayList<>(apex.getFindings());
                    if (matchingIpAsset != null) {
                        for (RiskFinding ipFinding : matchingIpAsset.getFindings()) {
                            if (!clusterFindings.contains(ipFinding)) {
                                clusterFindings.add(ipFinding);
                            }
                        }
                    }

                    if (!clusterFindings.isEmpty()) {
                        out.println("  Cluster Vulnerability Findings:");
                        clusterFindings.forEach(f ->
                                out.printf("    - [%-8s] (%-14s) %s%n", f.severity(), f.category(), f.message()));
                    } else {
                        out.println("  Cluster Vulnerability Findings: None detected.");
                    }
                    out.println("-------------------------------------------------------------------------------");
                }
            }

            out.println("\n2. STANDALONE IP INFRASTRUCTURE & OPEN PORTS AUDIT");
            out.println("-------------------------------------------------------------------------------");
            List<IpAsset> ipAssets = exportScope.stream()
                    .filter(a -> a instanceof IpAsset)
                    .map(a -> (IpAsset) a)
                    .toList();

            if (ipAssets.isEmpty()) {
                out.println("No standalone IP assets in this export scope.");
            } else {
                for (IpAsset ip : ipAssets) {
                    out.printf("IP HOST: %s [ID: %s] | Open Ports: %d%n",
                            ip.getValue(), ip.getId(), ip.getOpenPorts().size());
                    if (!ip.getOpenPorts().isEmpty()) {
                        ip.getOpenPorts().forEach((port, banner) ->
                                out.printf("  - Port %-5d : %s%n", port, banner));
                    }
                    if (!ip.getFindings().isEmpty()) {
                        out.println("  Vulnerabilities:");
                        ip.getFindings().forEach(f ->
                                out.printf("    - [%-8s] (%-14s) %s%n", f.severity(), f.category(), f.message()));
                    }
                    out.println("-------------------------------------------------------------------------------");
                }
            }

            out.println("\n===============================================================================");
            out.println("                               END OF REPORT                                   ");
            out.println("===============================================================================");

            System.out.println("[+] Audit report exported successfully to file: " + filename);

        } catch (Exception e) {
            System.out.println("[-] Error exporting report: " + e.getMessage());
        }
    }

    private static void runRiskAudit() {
        listAssets();
        System.out.print("Enter ID of the Asset that required further analysis:");
        var targetId = scanner.nextLine().trim();

        var target = inventory.stream()
                .filter(a -> a.getId().equalsIgnoreCase(targetId))
                .findFirst()
                .orElse(null);

        if (target == null) {
            System.out.println("[-] Your Asset is not found.");
            return;
        }

        target.printAuditSummary();

        riskEngine.inspectAssetWithPatternMatching(target, auditScanner, inventory);

        System.out.println("\n--- IDENTIFIED RISK FINDINGS ---");
        if (target.getFindings().isEmpty()) {
            System.out.println("[+] No active vulnerabilities or posture deviations detected.");
        } else {
            target.getFindings().forEach(f ->
                    System.out.printf("  [%-8s] (%-14s) %s%n", f.severity(), f.category(), f.message()));
        }
    }

    private static void deleteAsset() {
        listAssets();
        System.out.print("Input ID of the Asset you wanna delete: ");
        var deleteId = scanner.nextLine().trim();

        var target = inventory.stream()
                .filter(a -> a.getId().equalsIgnoreCase(deleteId))
                .findFirst()
                .orElseThrow(() -> new AssetNotFoundException("[-] Not Found Asset with ID " + deleteId + " to delete!"));

        var snap = new AssetSnapshot(
                target.getId(), target.getValue(), target.getAssetCategory(),
                target.getEnvironment(), target.getExposure(),
                target.getFindings().size(), java.time.Instant.now()
        );
        snapshots.add(snap);

        inventory.remove(target);
        System.out.println("[+] Successfully Deleted asset with ID " + deleteId + " and save to snapshots");
    }

    private static void displaySnapshots() {
        if (snapshots.isEmpty()) {
            System.out.println("[-] No snapshot was recorded");
            return;
        }
        var dtf = DateTimeFormatter.ISO_INSTANT;
        System.out.println("\n--- LIST OF SNAPSHOT HISTORY ---");
        for (AssetSnapshot s : snapshots) {
            System.out.printf("Snapshot ID: %s | Value: %s | Category: %s | Risks: %d | Time: %s%n",
                    s.id(), s.value(), s.type(), s.riskCount(), dtf.format(s.snapshotTime()));
        }
    }

    private boolean askToContinueOrExit() {
        System.out.println();
        System.out.print("Continue? (y/n): ");
        System.out.flush();
        String input = scanner.nextLine().trim().toLowerCase();
        return !(input.equals("n") || input.equals("no"));
    }

    private void loadFromFile() {
        Path path = Path.of(DATA_FILE);
        if (!Files.exists(path)) {
            System.out.println("[*] Not Found " + DATA_FILE + ". Initializing Data Sample");
            seedSampleData();
            saveToFile();
            return;
        }

        inventory.clear();
        int maxId = 100;

        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String[] parts = line.split("\\|");
                if (parts.length < 7) continue;

                String type = parts[0];
                String id = parts[1];
                String value = parts[2];
                Environment env = Environment.valueOf(parts[3]);
                Exposure exp = Exposure.valueOf(parts[4]);
                OwnerContact owner = new OwnerContact(parts[5], parts[6]);

                try {
                    int num = Integer.parseInt(id.replaceAll("\\D+", ""));
                    if (num > maxId) maxId = num;
                } catch (NumberFormatException ignored) {
                }

                switch (type) {
                    case "DOMAIN" -> inventory.add(new DomainAsset(id, value, env, exp, owner));
                    case "IP" -> {
                        String ipRange = parts.length > 7 ? parts[7] : "/32";
                        IpAsset ip = new IpAsset(id, value, env, exp, owner, ipRange);

                        if (parts.length > 8 && !parts[8].isBlank()) {
                            String[] portEntries = parts[8].split(",");
                            for (String pe : portEntries) {
                                String[] pTokens = pe.split(":");
                                if (pTokens.length == 2) {
                                    ip.addOpenPort(Integer.parseInt(pTokens[0].trim()), pTokens[1].trim());
                                }
                            }
                        }
                        inventory.add(ip);
                    }
                }
            }
            idSequence = maxId;
            System.out.println("[+] Successfully Import " + inventory.size() + " Assets from file " + DATA_FILE);
        } catch (IOException e) {
            System.out.println("[-] Error while importing data: " + e.getMessage() + ". Use the data sample instead.");
            seedSampleData();
        }
    }

    private void saveToFile() {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Path.of(DATA_FILE)))) {
            for (Asset a : inventory) {
                var sb = new StringBuilder();

                if (a instanceof DomainAsset d) {
                    sb.append("DOMAIN|")
                            .append(d.getId()).append("|")
                            .append(d.getValue()).append("|")
                            .append(d.getEnvironment()).append("|")
                            .append(d.getExposure()).append("|")
                            .append(d.getOwner().getTeamName()).append("|")
                            .append(d.getOwner().getEmail());
                } else if (a instanceof IpAsset ip) {
                    sb.append("IP|")
                            .append(ip.getId()).append("|")
                            .append(ip.getValue()).append("|")
                            .append(ip.getEnvironment()).append("|")
                            .append(ip.getExposure()).append("|")
                            .append(ip.getOwner().getTeamName()).append("|")
                            .append(ip.getOwner().getEmail()).append("|")
                            .append(ip.getIpRange()).append("|");
                    StringJoiner sj = new StringJoiner(",");
                    ip.getOpenPorts().forEach((p, banner) -> sj.add(p + ":" + banner));
                    sb.append(sj);
                }
                writer.println(sb);
            }
            System.out.println("[+] Successfully Synchronized Data to file: " + DATA_FILE);
        } catch (IOException e) {
            System.out.println("[-] Error while exporting data to file: " + e.getMessage());
        }
    }

    private static Optional<Asset> findExistingAsset(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalizedValue = value.trim();
        return inventory.stream()
                .filter(asset -> asset.getValue().equalsIgnoreCase(normalizedValue))
                .findFirst();
    }
}

