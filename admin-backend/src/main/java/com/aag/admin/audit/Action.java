package com.aag.admin.audit;

public enum Action {

    POLICY_REQUEST("정책 조회"),
    POLICY_CREATE("정책 생성"),
    POLICY_UPDATE("정책 수정"),
    POLICY_DELETE("정책 삭제"),
    POLICY_ACTIVATE("정책 활성화");

    private final String description;

    Action(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static Action stringValueOf(String value) {
        if (value == null || value.isEmpty()) {
            throw new AssertionError("Unknown Action");
        }
        for (Action action : values()) {
            if (action.name().equals(value)) {
                return action;
            }
        }
        throw new AssertionError("Unknown Action");
    }
}
