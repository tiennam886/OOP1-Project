import engine.RiskEngine;
import model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class AttackSurfaceManager {
    private final List<Asset> inventory = new ArrayList<>();
    private final List<AssetSnapshot> snapshots = new ArrayList<>();
    private final Scanner scanner = new Scanner(System.in);
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

                switch (scanner.nextLine().trim()) {
                    case "1" -> addAsset();
                    case "2" -> listAssets();
                    case "3" -> runDiscovery();
                    case "4" -> runAudit();
                    case "5" -> showRiskDashboard();
                    case "6" -> exportReport();
                    case "0" -> {
                        IO.print("[+] Saved data to JSON file . Goodbye!");
                        isRunning = false;
                    }
                    default -> IO.println("[-] Invalid Option");
                }
            }

        }
        scanner.close();
    }

    private static void addAsset() {
        IO.print("Enter domain to add (e.g., example.com): ");
    }

    private static void listAssets() {
        IO.print("List of entered domain:");
    }

    private static void runDiscovery() {
        IO.print("runDiscovery");
    }

    private static void runAudit() {
        IO.print("runAudit");
    }

    private static void showRiskDashboard() {
        IO.print("showRiskDashboard");
    }

    private static void exportReport() {
        IO.print("Enter name of file to export:");
    }
}

