package com.aag.admin.audit;

public enum ActorType {

    GATEWAY("1"),
    ADMIN("0");

    private final String description;

    ActorType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static ActorType stringValueOf(String value) {
        if (value == null || value.isEmpty()) {
            throw new AssertionError("Unknown ActorType");
        }
        for (ActorType type : values()) {
            if (type.name().equals(value)) {
                return type;
            }
        }
        throw new AssertionError("Unknown ActorType");
    }
}
