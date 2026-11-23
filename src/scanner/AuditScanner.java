package scanner;

import model.RiskFinding;
import model.Severity;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

public class AuditScanner {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?=.{1,253}$)(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-_]{1,63}(?<!-))*$"
    );

    private boolean isValidDomain(String host) {
        return host != null && DOMAIN_PATTERN.matcher(host).matches();
    }

    public List<RiskFinding> checkTls(String host, int port) {
        List<RiskFinding> findings = new ArrayList<>();
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(3000);
                socket.startHandshake();

                var certs = socket.getSession().getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate cert) {
                    Instant notAfter = cert.getNotAfter().toInstant();
                    long daysLeft = ChronoUnit.DAYS.between(Instant.now(), notAfter);

                    if (daysLeft < 0) {
                        findings.add(new RiskFinding(Severity.CRITICAL, "TLS", "TLS Certificate was expired"));
                    } else if (daysLeft < 15) {
                        findings.add(new RiskFinding(Severity.HIGH, "TLS", "TLS Certificate will be expired within " + daysLeft + " days"));
                    } else if (daysLeft < 30) {
                        findings.add(new RiskFinding(Severity.MEDIUM, "TLS", "TLS Certificate will be expired within " + daysLeft + " days"));
                    }
                }
            }
        } catch (Exception e) {
            findings.add(new RiskFinding(Severity.INFO, "TLS", "Cannot check TLS via port " + port + ": " + e.getMessage()));
        }
        return findings;
    }

    public List<RiskFinding> checkHttpAndCors(String host) {
        List<RiskFinding> findings = new ArrayList<>();
        String url = (host.startsWith("http://") || host.startsWith("https://")) ? host : "https://" + host;

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Origin", "https://evil-attacker.com")
                    .timeout(Duration.ofSeconds(6))
                    .GET()
                    .build();

            HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            HttpHeaders headers = resp.headers();

            if (headers.firstValue("Strict-Transport-Security").isEmpty()) {
                findings.add(new RiskFinding(Severity.MEDIUM, "HTTP_HEADER", "Missing header HSTS (Strict-Transport-Security)"));
            }
            if (headers.firstValue("Content-Security-Policy").isEmpty()) {
                findings.add(new RiskFinding(Severity.LOW, "HTTP_HEADER", "Missing header CSP (Content-Security-Policy)"));
            }
            if (headers.firstValue("X-Frame-Options").isEmpty()) {
                findings.add(new RiskFinding(Severity.LOW, "HTTP_HEADER", "Missing header against Clickjacking (X-Frame-Options)"));
            }
            if (headers.firstValue("X-Content-Type-Options").isEmpty()) {
                findings.add(new RiskFinding(Severity.LOW, "HTTP_HEADER", "Missing header X-Content-Type-Options: nosniff"));
            }

            headers.firstValue("Access-Control-Allow-Origin").ifPresent(val -> {
                if ("*".equals(val) || val.contains("evil-attacker.com")) {
                    findings.add(new RiskFinding(Severity.HIGH, "CORS", "CORS was not configured strictly: " + val));
                }
            });

        } catch (Exception e) {
            findings.add(new RiskFinding(Severity.INFO, "HTTP", "Cannot check HTTP headers: " + e.getMessage()));
        }
        return findings;
    }

    public List<RiskFinding> checkEmailGovernance(String domain) {
        List<RiskFinding> findings = new ArrayList<>();

        try {
            List<String> txtRecords = queryTxtDns(domain);
            boolean hasSpf = txtRecords.stream().anyMatch(r -> r.contains("v=spf1"));
            if (!hasSpf) {
                findings.add(new RiskFinding(Severity.HIGH, "EMAIL_SECURITY", "Missing SPF (risk of spoofing email)"));
            }

            List<String> dmarcRecords = queryTxtDns("_dmarc." + domain);
            boolean hasDmarc = dmarcRecords.stream().anyMatch(r -> r.contains("v=DMARC1"));
            if (!hasDmarc) {
                findings.add(new RiskFinding(Severity.HIGH, "EMAIL_SECURITY", "Missing DMARC record in _dmarc." + domain));
            }
        } catch (Exception ignored) {}
        return findings;
    }

    private List<String> queryTxtDns(String host) {
        List<String> records = new ArrayList<>();
        if (!isValidDomain(host)) {
            return records;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("nslookup", "-type=TXT", host);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            try (Scanner s = new Scanner(process.getInputStream())) {
                while (s.hasNextLine()) {
                    String line = s.nextLine().trim();
                    if (line.contains("text =") || line.contains("v=spf1") || line.contains("v=DMARC1")) {
                        records.add(line);
                    }
                }
            }
        } catch (Exception ignored) {}
        return records;
    }
}
