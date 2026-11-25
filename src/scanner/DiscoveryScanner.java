package scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiscoveryScanner {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public static final List<Integer> DEFAULT_PORTS = List.of(
            21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8000, 8081, 8443, 9200, 27017
    );
    public Set<String> discoverSubdomains(String domain) {
        Set<String> results = new TreeSet<>();
        String normalizedDomain = domain.trim().toLowerCase();
        String crtUrl = "https://crt.sh/?q=%25." + normalizedDomain + "&output=json";
        boolean crtSuccess = fetchSubdomains(crtUrl, normalizedDomain, results, "crt.sh");
        if (!crtSuccess || results.isEmpty()) {
            System.out.println("[*] Primary service crt.sh failed/unavailable. Triggering automatic failover to ctlogs.dev...");
            String ctlogsUrl = "[suspicious link removed]." + normalizedDomain + "&output=json";
            fetchSubdomains(ctlogsUrl, normalizedDomain, results, "ctlogs.dev");
        }
        return results;
    }
    private boolean fetchSubdomains(String targetUrl, String domain, Set<String> results, String providerName) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("User-Agent", "Defensive-ASM-Scanner/1.0")
                    .timeout(Duration.ofSeconds(12))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                parseSubdomainsFromResponse(response.body(), domain, results);
                System.out.printf("[+] Successfully queried %s (%d unique subdomains found)%n", providerName, results.size());
                return true;
            } else {
                System.out.printf("[-] %s returned HTTP error status: %d (Failover candidate)%n", providerName, response.statusCode());
                return false;
            }
        } catch (Exception e) {
            System.out.printf("[-] Failed to query %s: %s%n", providerName, e.getMessage());
            return false;
        }
    }

    private void parseSubdomainsFromResponse(String responseBody, String domain, Set<String> results) {
        if (responseBody == null || responseBody.isBlank()) return;

        Pattern pattern = Pattern.compile("\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(responseBody);
        while (matcher.find()) {
            String token = matcher.group(1);
            for (String line : token.split("\\\\n|\n")) {
                String cleaned = line.trim().toLowerCase().replace("*.", "");
                if (cleaned.endsWith("." + domain) && !cleaned.equals("." + domain) && !cleaned.contains(" ")) {
                    results.add(cleaned);
                }
            }
        }
    }

    public Map<Integer, String> scanPorts(String host, List<Integer> ports) {
        Map<Integer, String> openPorts = new ConcurrentSkipListMap<>();
        ExecutorService executor = Executors.newFixedThreadPool(20);
        List<Future<?>> futures = new ArrayList<>();
        for (int port : ports) {
            futures.add(executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), 600);
                    socket.setSoTimeout(1000);

                    String banner = grabBanner(socket, port);
                    openPorts.put(port, banner);
                } catch (Exception ignored) {
                }
            }));
        }
        for (Future<?> f : futures) {
            try { f.get(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
        }
        executor.shutdown();
        return new TreeMap<>(openPorts);
    }

    private String grabBanner(Socket socket, int port) {
        try {
            if (port == 80 || port == 8080) return "HTTP-Service";
            if (port == 443 || port == 8443) return "HTTPS/TLS-Service";

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            char[] buffer = new char[1024];
            int read = reader.read(buffer, 0, buffer.length);
            if (read > 0) {
                return new String(buffer, 0, read).trim().replaceAll("[\\r\\n]+", " ");
            }
        } catch (Exception ignored) {}
        return "Open-UnknownService";
    }
}
