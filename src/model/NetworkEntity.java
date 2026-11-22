package model;

import java.time.LocalDate;

public abstract class NetworkEntity {
    private String entityName;
    private LocalDate registeredDate;

    public NetworkEntity(String entityName, LocalDate registeredDate) {
        this.entityName = entityName;
        this.registeredDate = registeredDate;
    }

    public String getEntityName() { return entityName; }
    public LocalDate getRegisteredDate() { return registeredDate; }
}
