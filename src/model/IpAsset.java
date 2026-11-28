package model;

import java.time.LocalDate;
import java.util.Map;
import java.util.TreeMap;

public final class IpAsset extends Asset {
    private final Map<Integer, String> openPorts = new TreeMap<>();
    private final String ipRange;

    public IpAsset(String id, String ipAddress, Environment env, Exposure exp, OwnerContact owner, String ipRange) {
        super(id, ipAddress, env, exp, owner, LocalDate.now());
        this.ipRange = ipRange != null ? ipRange : "/32";
    }

    public void addOpenPort(int port, String banner) {
        this.openPorts.put(port, banner);
    }

    public Map<Integer, String> getOpenPorts() {
        return new TreeMap<>(this.openPorts);
    }

    public String getIpRange() { return ipRange; }

    @Override
    public String getAssetCategory() {
        return "IP_HOST";
    }

    @Override
    public int calculateRiskScore() {
        int score = getFindings().stream().mapToInt(f -> f.severity().getWeight()).sum();
        score += openPorts.size() * 2;
        return score;
    }
}
