void main() {
    Scanner scanner = new Scanner(System.in);
    boolean isRunning = true;
    while (isRunning) {
        while (isRunning) {
            System.out.println("\n=== DEFENSIVE ATTACK SURFACE MANAGEMENT (ASM) CLI ===");
            System.out.println("1. Add & Categorize Inventory (Domain / Subdomain / IP / ASN / Cloud)");
            System.out.println("2. List Inventory");
            System.out.println("3. Discover Inventory (Subdomain crt.sh & Port/Banner Scan)");
            System.out.println("4. Audit Configuration & Discover Risks (DNS/Email, TLS, HTTP/CORS, Ports)");
            System.out.println("5. Risk Dashboard");
            System.out.println("6. Export Report to file TXT");
            System.out.println("0. Exit");
            System.out.print("Choose an option (0-6): ");

            switch (scanner.nextLine().trim()) {
                case "1" -> addAsset();
                case "2" -> listAssets();
                case "3" -> runDiscovery();
                case "4" -> runAudit();
                case "5" -> showRiskDashboard();
                case "6" -> exportReport();
                case "0" -> {
                    System.out.println("[+] Saved data to JSON file . Goodbye!");
                    isRunning = false;
                }
                default -> System.out.println("[-] Invalid Option");
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

