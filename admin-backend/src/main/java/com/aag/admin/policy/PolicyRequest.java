package com.aag.admin.policy;

import jakarta.validation.constraints.NotBlank;

public class PolicyRequest {

    @NotBlank
    private String name;

    private String description;

    @NotBlank
    private String ruleType;

    @NotBlank
    private String pattern;

    private boolean enabled;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getRuleType() { return ruleType; }
    public void setRuleType(String ruleType) { this.ruleType = ruleType; }
    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
