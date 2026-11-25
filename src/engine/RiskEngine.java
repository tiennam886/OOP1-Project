package engine;

import model.*;
import scanner.AuditScanner;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

public class RiskEngine {
    public List<RiskFinding> evaluatePort(int port, String serviceName) {
        String riskVerdict = switch (port) {
            case 21, 23 -> "Critical risk: Cleartext unencrypted protocol exposed (FTP/Telnet)";
            case 3389, 445 -> "Dangerous administrative remote management port exposed (RDP/SMB)";
            case int p when (p == 3306 || p == 5432 || p == 6379 || p == 27017) ->
                    "Direct database/cache instance exposed: " + serviceName;
            case int p when p < 1024 ->
                    "Privileged system port open: " + p;
            default -> "Standard operational service port: " + port;
        };

        Severity sev = (port == 21 || port == 23 || port == 3389 || port == 445 ||
                port == 3306 || port == 5432 || port == 6379)
                ? Severity.CRITICAL : Severity.INFO;

        return List.of(new RiskFinding(sev, "NETWORK_PORT", riskVerdict));
    }

    public void inspectAssetWithPatternMatching(Asset asset, AuditScanner auditScanner, List<Asset> inventory) {
        if (asset == null || auditScanner == null) return;

        System.out.println("\n[*] Executing contextual audit dispatch via Switch Pattern Matching:");

        switch (asset) {
            case DomainAsset d when d.getAssetCategory().equals("APEX_DOMAIN") -> {
                System.out.println("  -> [APEX DOMAIN] Triggering Root DNS, Email Governance, TLS, HTTP & CVE-2026-123007 audits...");
                auditScanner.checkEmailGovernance(d.getValue())
                        .forEach(f -> d.addFinding(f.severity(), f.category(), "[" + d.getValue() + "] " + f.message()));

                auditDomainTarget(d, d.getValue(), auditScanner);
                Set<String> targetSubdomains = new TreeSet<>(d.getSubdomains());

                if (inventory != null) {
                    inventory.stream()
                            .filter(a -> a instanceof DomainAsset)
                            .map(Asset::getValue)
                            .filter(val -> val.endsWith("." + d.getValue()) && !val.equalsIgnoreCase(d.getValue()))
                            .forEach(targetSubdomains::add);
                }

                if (!targetSubdomains.isEmpty()) {
                    System.out.printf("%n  [+] Auto-auditing %d related subdomains for %s:%n",
                            targetSubdomains.size(), d.getValue());
                    for (String sub : targetSubdomains) {
                        System.out.println("     * Auditing subdomain target: " + sub);
                        auditDomainTarget(d, sub, auditScanner);
                    }
                } else {
                    System.out.println("  [*] No child subdomains registered yet. (Tip: Run Option 3 'Discovery' first).");
                }
            }
            case DomainAsset d -> {
                System.out.println("  -> [SUBDOMAIN] Inspecting CNAME Takeover vectors, TLS validity & HTTP Headers...");
                auditDomainTarget(d, d.getValue(), auditScanner);
            }
            case IpAsset ip when ip.getOpenPorts().size() > 5 -> {
                System.out.println("  -> [HIGH ALERT IP] Excessively exposed host (" + ip.getOpenPorts().size() + " ports open)...");
                ip.addFinding(Severity.HIGH, "EXPOSURE", "Server exposes excessive network attack surface (>5 ports)");
                ip.getOpenPorts().forEach((port, banner) ->
                        evaluatePort(port, banner).forEach(ip::addFinding)
                );
            }
            case IpAsset ip -> {
                System.out.println("  -> [IP HOST] Evaluating open service ports via Java 27 Primitive Patterns...");
                ip.getOpenPorts().forEach((port, banner) ->
                        evaluatePort(port, banner).forEach(ip::addFinding)
                );
            }
            case CloudAsset c -> {
                System.out.println("  -> [CLOUD IAM] Auditing cloud boundary policies for " + c.getProvider());
                if (c.getExposure() == Exposure.PUBLIC) {
                    c.addFinding(Severity.CRITICAL, "CLOUD_IAM", "Cloud resource account perimeter exposed publicly");
                } else {
                    c.addFinding(Severity.INFO, "CLOUD_IAM", "Cloud account boundary properly restricted to VPC/Internal");
                }
            }
            default -> System.out.println("  -> Unrecognized asset category.");
        }

        System.out.printf("[+] Contextual audit complete. Total findings registered for %s: %d%n",
                asset.getValue(), asset.getFindings().size());
    }

    private void auditDomainTarget(Asset asset, String targetDomain, AuditScanner auditScanner) {
        Stream.of(
                auditScanner.checkTls(targetDomain, 443),
                auditScanner.checkHttpAndCors(targetDomain),
                auditScanner.checkNginxHttp2Vulnerability(targetDomain)
        ).flatMap(List::stream).forEach(f -> asset.addFinding(
                f.severity(),
                f.category(),
                String.format("[%s] %s", targetDomain, f.message())
        ));
    }
}
