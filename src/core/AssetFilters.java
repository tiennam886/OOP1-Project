package core;

import model.*;

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

public class AssetFilters {
    public static Predicate<Asset> byEnvironment(Environment... envs) {
        return asset -> Arrays.stream(envs)
                .anyMatch(env -> asset.getEnvironment() == env);
    }

    public static Predicate<Asset> isPublicExposed() {
        return asset -> asset.getExposure() == Exposure.PUBLIC;
    }

    public static Predicate<Asset> riskScoreAbove(int threshold) {
        return asset -> asset.calculateRiskScore() > threshold;
    }

    public static List<Asset> filterByApexDomainCluster(List<Asset> inventory, String apexDomainInput) {
        if (apexDomainInput == null || apexDomainInput.isBlank()) return List.of();
        String targetApex = apexDomainInput.trim().toLowerCase();

        DomainAsset apex = inventory.stream()
                .filter(a -> a instanceof DomainAsset)
                .map(a -> (DomainAsset) a)
                .filter(d -> d.getValue().equalsIgnoreCase(targetApex))
                .findFirst()
                .orElse(null);

        String associatedIp = (apex != null) ? apex.getAssociatedIp() : null;

        return inventory.stream()
                .filter(a -> {
                    if (a.getValue().equalsIgnoreCase(targetApex)) return true;

                    if (a instanceof DomainAsset d) {
                        if (d.getValue().endsWith("." + targetApex)) return true;
                        if (apex != null && apex.getSubdomains().contains(d.getValue().toLowerCase())) return true;
                    }

                    if (a instanceof IpAsset ip && associatedIp != null) {
                        return ip.getValue().equalsIgnoreCase(associatedIp);
                    }

                    return false;
                })
                .toList();
    }

    public static List<Asset> filterByOwner(List<Asset> inventory, String ownerQuery) {
        if (ownerQuery == null || ownerQuery.isBlank()) return List.of();
        String q = ownerQuery.trim().toLowerCase();

        return inventory.stream()
                .filter(a -> a.getOwner() != null && (
                                a.getOwner().getEmail().toLowerCase().contains(q) ||
                                a.getOwner().getTeamName().toLowerCase().contains(q)
                ))
                .toList();
    }
}
