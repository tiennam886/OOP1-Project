package core;

import model.Asset;
import model.Environment;
import model.Exposure;

import java.util.Arrays;
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
}
