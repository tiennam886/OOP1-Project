import core.AssetFilters;
import engine.RiskEngine;
import model.*;
import exception.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class AttackSurfaceManager {
    private static final List<Asset> inventory = new ArrayList<>();
    private final List<AssetSnapshot> snapshots = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);
    private final RiskEngine riskEngine = new RiskEngine();
    private static int idSequence = 100;

    static void main(String[] args) {
        var app = new AttackSurfaceManager();
        app.seedSampleData();
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
                    System.out.println("[*] Saved data to JSON file . Goodbye!");
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
                System.out.println("[*] Closing Program. Good bye!!");
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
        IO.print("runAudit");
    }

    private static void deleteAsset() {
        IO.print("showRiskDashboard");
    }

    private static void displaySnapshots() {
        IO.print("Enter name of file to export:");
    }

    private boolean askToContinueOrExit() {
        System.out.println();
        System.out.print("Continue? (y/n): ");
        System.out.flush();
        String input = scanner.nextLine().trim().toLowerCase();
        return input.equals("y") || input.equals("yes");
    }
}

