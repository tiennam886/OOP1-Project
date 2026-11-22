package core;

public interface Auditable {
    int calculateRiskScore();

    default void printAuditSummary() {
        System.out.println(formatAuditOutput(calculateRiskScore()));
    }

    static String complianceStandard() {
        return "ISO/IEC 27001 - Attack Surface Verification";
    }

    private String formatAuditOutput(int score) {
        StringBuilder sb = new StringBuilder();
        sb.append("[AUDIT RESULT] Compliance: ").append(complianceStandard()).append(" | Computed Risk Score: ").append(score);
        return sb.toString();
    }
}
