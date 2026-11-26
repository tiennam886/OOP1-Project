package model;

import core.Auditable;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

public abstract sealed class Asset extends NetworkEntity implements Auditable permits DomainAsset, IpAsset {
    private final String id;
    private final String value;
    private final Environment environment;
    private final Exposure exposure;
    private final OwnerContact owner; // Sử dụng Custom Immutable Type
    private final Instant lastScanned;
    private final List<RiskFinding> findings = new ArrayList<>();

    public Asset(String id, String value, Environment env, Exposure exp, OwnerContact owner, LocalDate regDate) {
        super(value, regDate != null ? regDate : LocalDate.now());
        this.id = id;
        this.value = value;
        this.environment = env;
        this.exposure = exp;
        this.owner = new OwnerContact(owner);
        this.lastScanned = Instant.now();
    }

    public Asset(String id, String value, Environment env) {
        this(id, value, env, Exposure.PUBLIC, new OwnerContact("DevSecOps", "devsec@company.com"), LocalDate.now());
    }

    public String getId() { return id; }
    public String getValue() { return value; }
    public Environment getEnvironment() { return environment; }
    public Exposure getExposure() { return exposure; }

    public OwnerContact getOwner() {
        return new OwnerContact(this.owner);
    }

    public List<RiskFinding> getFindings() {
        return Collections.unmodifiableList(findings); // Trả về unmodifiable view
    }

    public void addFinding(RiskFinding finding) {
        if (finding != null) findings.add(finding);
    }

    public void addFinding(Severity severity, String category, String message) {
        this.addFinding(new RiskFinding(severity, category, message));
    }

    public abstract String getAssetCategory();

    @Override
    public String toString() {
        return String.format("[%s] ID=%s, Value=%s, Env=%s, Exp=%s, Owner=%s, Risks=%d",
                getAssetCategory(), this.id, super.getEntityName(), this.environment, this.exposure, this.owner, findings.size());
    }

    public void printAuditSummary() {
        String scanTimeStr = (lastScanned != null) ? lastScanned.toString() : "Never Scanned";
        System.out.println("===============================================================================");
        System.out.printf("  [ASSET METADATA SUMMARY]%n");
        System.out.printf("  ID:           %-15s | Category:     %s%n", getId(), getAssetCategory());
        System.out.printf("  Target Value: %-15s | Environment:  %s%n", getValue(), getEnvironment());
        System.out.printf("  Exposure:     %-15s | Last Scanned: %s%n", getExposure(), scanTimeStr);
        System.out.println("===============================================================================");
    }
}
