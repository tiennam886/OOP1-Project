package engine;

import model.*;

import java.util.ArrayList;
import java.util.List;

public class RiskEngine {
    public List<RiskFinding> evaluatePort(int port, String serviceName) {
        List<RiskFinding> findings = new ArrayList<>();

        String riskVerdict = switch (port) {
            case 21, 23 -> "CRITICAL: Unencrypted Protocol (FTP/Telnet)";
            case 22, 3389, 445 -> "Remote Management Port exposed via Public Internet (SSH/RDP/SMB)";
            case int p when (p == 3306 || p == 5432 || p == 6379 || p == 27017) ->
                    "Database Management Port exposed via Public Internet: " + serviceName;
            case int p when p < 1024 ->
                    "Privileged Port is opening: " + p;
            default -> "Normal Service Port: " + port;
        };

        if (port == 21 || port == 23 || port == 3389 || port == 445 || port == 3306 || port == 5432 || port == 6379) {
            findings.add(new RiskFinding(Severity.CRITICAL, "NETWORK_PORT", riskVerdict));
        } else {
            findings.add(new RiskFinding(Severity.INFO, "PORT_INFO", riskVerdict));
        }
        return findings;
    }

    public void inspectAssetWithPatternMatching(Asset asset) {
        System.out.println("\n[*] Further Analysis via Pattern Matching:");
        switch (asset) {
            case DomainAsset d when d.getAssetCategory().equals("APEX_DOMAIN") ->
                    System.out.println("  -> [APEX DOMAIN] Scanning DNS Root Records & mail exchange for " + d.getValue());
            case DomainAsset d ->
                    System.out.println("  -> [SUBDOMAIN] Searching CNAME / Takeover records for " + d.getValue());
            case IpAsset ip when ip.getOpenPorts().size() > 5 ->
                    System.out.println("  -> [HIGH ALERT FOR IP HOST] IP has too many opening ports (" + ip.getOpenPorts().size() + " ports)");
            case IpAsset ip ->
                    System.out.println("  -> [IP HOST] Firewall and IDS/IPS scanning for IP " + ip.getValue());
            case CloudAsset c ->
                    System.out.println("  -> [CLOUD IAM] Auditing Privilege Permissions for Cloud Account (" + c.getProvider() + " ID=" + c.getAccountId() + ")");
            case null, default ->
                    System.out.println("  -> Unidentified Asset");
        }
    }
}
