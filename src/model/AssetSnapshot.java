package model;
import java.time.Instant;

public record AssetSnapshot(
        String id,
        String value,
        String type,
        Environment environment,
        Exposure exposure,
        int riskCount,
        Instant snapshotTime
) {
}
