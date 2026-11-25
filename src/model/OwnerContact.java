package model;

public final class OwnerContact {
    private final String teamName;
    private final String email;

    public OwnerContact(String teamName, String email) {
        this.teamName = (teamName == null || teamName.isBlank()) ? "SecOps-Unassigned" : teamName.trim();
        this.email = (email == null || email.isBlank()) ? "soc@internal.local" : email.trim();
    }

    // Defensive copy constructor
    public OwnerContact(OwnerContact other) {
        this(other != null ? other.teamName : null, other != null ? other.email : null);
    }

    public String getTeamName() { return teamName; }
    public String getEmail() { return email; }

    @Override
    public String toString() {
        return teamName + " <" + email + ">";
    }
}
