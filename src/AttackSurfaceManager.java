void main() {
    Scanner scanner = new Scanner(System.in);
    boolean isRunning = true;
    while (isRunning) {
        while (isRunning) {
            IO.println("\n=== ATTACK SURFACE MANAGEMENT CLI ===");
            IO.println("1. Add domain");
            IO.println("2. See domain list");
            IO.println("3. Get subdomain of domain in list");
            IO.println("4. Export to txt");
            IO.println("5. Exit");
            IO.print("Select an option (1-5): ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    addDomain();
                    break;
                case "2":
                    seeDomainList();
                    break;
                case "3":
                    getSubdomains();
                    break;
                case "4":
                    exportToTxt();
                    break;
                case "5":
                    IO.println("Exiting application...");
                    isRunning = false;
                    break;
                default:
                    IO.println("Invalid selection! Please enter a number from 1 to 5.");
            }
        }

    }
    scanner.close();
}

private static void addDomain() {
    IO.print("Enter domain to add (e.g., example.com): ");
}

private static void seeDomainList() {
    IO.print("List of entered domain:");
}

private static void getSubdomains() {
    IO.print("List of subdomains:");
}

private static void exportToTxt() {
    IO.print("Enter name of file to export:");
}

