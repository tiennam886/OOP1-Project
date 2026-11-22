import core.AssetFilters;
import engine.RiskEngine;
import model.*;
import exception.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.StringJoiner;

public class AttackSurfaceManager {
    private static final String DATA_FILE = "assets.txt";
    private static final List<Asset> inventory = new ArrayList<>();
    private static final List<AssetSnapshot> snapshots = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);
    private static final RiskEngine riskEngine = new RiskEngine();
    private static int idSequence = 100;

    static void main() {
        var app = new AttackSurfaceManager();
        app.run();
    }

    private void seedSampleData() {
        // Initialize Sample Data
        var owner = new OwnerContact("RedTeam-Ops", "red@company.com");
        var d1 = new DomainAsset("A-" + (++idSequence), "corp-portal.com", Environment.PROD, Exposure.PUBLIC, owner);
        d1.addSubdomain("[suspicious link removed]");
        d1.addSubdomain("[suspicious link removed]");
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
                        4. Run Risk Evaluation
                        5. Remove an Asset
                        6. Show Snapshots History
                        0. Exit
                        Choose an option (0-6):\s""";
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
                    case "4" -> runRiskAudit();
                    case "5" -> deleteAsset();
                    case "6" -> displaySnapshots();
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
            System.out.print("Choose an Asset Type (1: DOMAIN, 2: IP, 3: CLOUD): ");
            var typeChoice = scanner.nextLine().trim();

            System.out.print("Input Asset's Value (EX: example.com, 1.1.1.1, AWS-Prod): ");
            var val = scanner.nextLine().trim();
            if (val.isEmpty()) throw new InvalidAssetException("Asset's value can not be empty!");

            System.out.print("Environment (1: PROD, 2: STAGING, 3: DEV): ");
            var env = switch (scanner.nextLine().trim()) {
                case "1" -> Environment.PROD;
                case "2" -> Environment.STAGING;
                default -> Environment.DEV;
            };

            System.out.print("Exposure Perimeter (1: PUBLIC, 2: INTERNAL): ");
            var exp = "2".equals(scanner.nextLine().trim()) ? Exposure.INTERNAL : Exposure.PUBLIC;

            System.out.print("Contact of Owner: ");
            var team = scanner.nextLine().trim();
            var owner = new OwnerContact(team, team.toLowerCase() + "@company.com");

            var newId = "A-" + (++idSequence);
            Asset newAsset = switch (typeChoice) {
                case "1" -> new DomainAsset(newId, val, env, exp, owner);
                case "2" -> new IpAsset(newId, val, env, exp, owner, "/32");
                case "3" -> new CloudAsset(newId, val, env, owner, "AWS", "ACC-9988");
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
        System.out.print("Choose Filter (1: Only PROD, 2: Only PUBLIC, 3: Risk Score > 5): ");
        var fChoice = scanner.nextLine().trim();

        final int minThreshold = 5;

        List<Asset> filtered = switch (fChoice) {
            case "1" -> inventory.stream().filter(AssetFilters.byEnvironment(Environment.PROD)).toList();
            case "2" -> inventory.stream().filter(AssetFilters.isPublicExposed()).toList();
            case "3" -> inventory.stream().filter(AssetFilters.riskScoreAbove(minThreshold)).toList();
            default -> inventory;
        };

        if (filtered.isEmpty()) {
            System.out.println("[-] Not Found suitable asset");
            return;
        }

        System.out.printf("\n[+] FILTER RESULT (%d MATCHED ASSETS):%n", filtered.size());
        System.out.printf("%-4s %-8s %-28s %-14s %-8s %-9s %-10s%n",
                "NO", "ID", "VALUE", "TYPE", "ENV", "EXPOSURE", "SCORE");
        System.out.println("-".repeat(85));

        for (int i = 0; i < filtered.size(); i++) {
            Asset a = filtered.get(i);
            System.out.printf("%-4d %-8s %-28s %-14s %-8s %-9s %-10d%n",
                    (i + 1),
                    a.getId(),
                    a.getValue(),
                    a.getAssetCategory(),
                    a.getEnvironment(),
                    a.getExposure(),
                    a.calculateRiskScore()
            );
        }
        System.out.println("-".repeat(85));
    }

    private static void runRiskAudit() {
        listAssets();
        System.out.print("Enter ID of the Asset that required further analysis:");
        var targetId = scanner.nextLine().trim();

        var asset = inventory.stream()
                .filter(a -> a.getId().equalsIgnoreCase(targetId))
                .findFirst()
                .orElse(null);

        if (asset == null) {
            System.out.println("[-] Your Asset is not found.");
            return;
        }

        asset.printAuditSummary();

        riskEngine.inspectAssetWithPatternMatching(asset);

        if (asset instanceof IpAsset ip) {
            System.out.println("[*] Running Analysis:");
            ip.getOpenPorts().forEach((port, banner) -> {
                var portFindings = riskEngine.evaluatePort(port, banner);
                portFindings.forEach(f -> System.out.println("   " + f));
            });
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
        return input.equals("y") || input.equals("yes");
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
                } catch (NumberFormatException ignored) {}

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
                    case "CLOUD" -> {
                        String provider = parts.length > 7 ? parts[7] : "AWS";
                        String accountId = parts.length > 8 ? parts[8] : "ACC-DEFAULT";
                        inventory.add(new CloudAsset(id, value, env, owner, provider, accountId));
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

                    // Serialize map openPorts: 3306:MySQL,22:SSH
                    StringJoiner sj = new StringJoiner(",");
                    ip.getOpenPorts().forEach((p, banner) -> sj.add(p + ":" + banner));
                    sb.append(sj);
                } else if (a instanceof CloudAsset c) {
                    sb.append("CLOUD|")
                            .append(c.getId()).append("|")
                            .append(c.getValue()).append("|")
                            .append(c.getEnvironment()).append("|")
                            .append(c.getExposure()).append("|")
                            .append(c.getOwner().getTeamName()).append("|")
                            .append(c.getOwner().getEmail()).append("|")
                            .append(c.getProvider()).append("|")
                            .append(c.getAccountId());
                }
                writer.println(sb);
            }
            System.out.println("[+] Successfully Synchronized Data to file: " + DATA_FILE);
        } catch (IOException e) {
            System.out.println("[-] Error while exporting data to file: " + e.getMessage());
        }
    }
}

