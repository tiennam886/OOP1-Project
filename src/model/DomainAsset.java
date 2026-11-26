package model;

import java.time.LocalDate;
import java.util.Set;
import java.util.TreeSet;

public final class DomainAsset extends Asset {
    private final Set<String> subdomains = new TreeSet<>();
    private final boolean isApex;
    private String associatedIp;

    public DomainAsset(String id, String domainName, Environment env, Exposure exp, OwnerContact owner) {
        LocalDate now = LocalDate.now();
        String normalizedDomain = (domainName != null) ? domainName.trim().toLowerCase() : "unknown.local";

        super(id, normalizedDomain, env, exp, owner, now);
        this.isApex = !normalizedDomain.startsWith("www.") && normalizedDomain.split("\\.").length == 2;
    }

    public DomainAsset(String id, String domainName) {
        this(id, domainName, Environment.PROD, Exposure.PUBLIC, new OwnerContact("Domain-Admin", "dns@company.com"));
    }

    public void addSubdomain(String sub) {
        subdomains.add(sub.toLowerCase());
    }

    public Set<String> getSubdomains() {
        return new TreeSet<>(subdomains); // Defensive copy
    }

    public void setAssociatedIp(String associatedIp) {
        this.associatedIp = associatedIp;
    }

    public String getAssociatedIp() {
        return associatedIp;
    }

    @Override
    public String getAssetCategory() {
        return isApex ? "APEX_DOMAIN" : "SUBDOMAIN";
    }

    @Override
    public int calculateRiskScore() {
        int score = getFindings().stream().mapToInt(f -> f.severity().getWeight()).sum();
        if (getExposure() == Exposure.PUBLIC) score += 5;
        return score;
    }
}
