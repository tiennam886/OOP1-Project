package model;

import java.time.LocalDate;

public final class CloudAsset extends Asset {
    private final String provider; // AWS, AZURE, GCP
    private final String accountId;

    public CloudAsset(String id, String accountName, Environment env, OwnerContact owner, String provider, String accountId) {
        super(id, accountName, env, Exposure.INTERNAL, owner, LocalDate.now());
        this.provider = provider.toUpperCase();
        this.accountId = accountId;
    }

    public String getProvider() { return provider; }
    public String getAccountId() { return accountId; }

    @Override
    public String getAssetCategory() {
        return "CLOUD_" + provider;
    }

    @Override
    public int calculateRiskScore() {
        return getFindings().stream().mapToInt(f -> f.severity().getWeight()).sum();
    }
}
