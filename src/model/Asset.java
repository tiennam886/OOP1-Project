package model;

import core.Auditable;
import exception.InvalidAssetException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

public abstract sealed class Asset extends NetworkEntity implements Auditable permits DomainAsset, IpAsset, CloudAsset {
    private final String id;
    private final String value;
    private Environment environment;
    private Exposure exposure;
    private OwnerContact owner; // Sử dụng Custom Immutable Type
    private Instant lastScanned;
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
    public void setEnvironment(Environment environment) { this.environment = environment; }
    public Exposure getExposure() { return exposure; }
    public void setExposure(Exposure exposure) { this.exposure = exposure; }

    public OwnerContact getOwner() {
        return new OwnerContact(this.owner);
    }
    public void setOwner(OwnerContact owner) {
        this.owner = new OwnerContact(owner);
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

    public Instant getLastScanned() { return lastScanned; }
    public void setLastScanned(Instant lastScanned) { this.lastScanned = lastScanned; }

    public abstract String getAssetCategory();

    @Override
    public String toString() {
        return String.format("[%s] ID=%s, Value=%s, Env=%s, Exp=%s, Owner=%s, Risks=%d",
                getAssetCategory(), this.id, super.getEntityName(), this.environment, this.exposure, this.owner, findings.size());
    }
}
