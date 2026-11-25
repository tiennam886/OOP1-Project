package model;

import java.time.Instant;

public record RiskFinding(Severity severity, String category, String message, Instant detectedAt) {
    public RiskFinding(Severity severity, String category, String message) {
        this(severity, category, message, Instant.now());
    }
}
