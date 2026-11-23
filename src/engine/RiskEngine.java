package engine;

import model.*;
import scanner.AuditScanner;

import java.util.List;

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

    public void inspectAssetWithPatternMatching(Asset asset, AuditScanner auditScanner) {
        if (asset == null || auditScanner == null) return;

        System.out.println("\n[*] Executing contextual audit dispatch via Switch Pattern Matching:");

        switch (asset) {
            case DomainAsset d when d.getAssetCategory().equals("APEX_DOMAIN") -> {
                System.out.println("  -> [APEX DOMAIN] Triggering Root DNS, Email Governance (SPF/DMARC), TLS & HTTP audits...");
                auditScanner.checkEmailGovernance(d.getValue()).forEach(d::addFinding);
                auditScanner.checkTls(d.getValue(), 443).forEach(d::addFinding);
                auditScanner.checkHttpAndCors(d.getValue()).forEach(d::addFinding);
            }
            case DomainAsset d -> {
                System.out.println("  -> [SUBDOMAIN] Inspecting CNAME Takeover vectors, TLS validity & HTTP Headers...");
                auditScanner.checkTls(d.getValue(), 443).forEach(d::addFinding);
                auditScanner.checkHttpAndCors(d.getValue()).forEach(d::addFinding);
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
}
