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
        return "[AUDIT RESULT] Compliance: " + complianceStandard() + " | Computed Risk Score: " + score;
    }
}
