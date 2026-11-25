package model;

public enum Severity {
    CRITICAL(10), HIGH(7), MEDIUM(4), LOW(2), INFO(0);
    private final int weight;
    Severity(int weight) { this.weight = weight; }
    public int getWeight() { return weight; }
}
