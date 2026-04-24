package com.aag.admin.policy;

import jakarta.validation.constraints.NotBlank;

public class PolicyRequest {

    @NotBlank
    private String name;

    private String description;

    private boolean l1Enabled;
    private boolean l2Enabled;
    private boolean l3Enabled;
    private boolean l4Enabled;
    private boolean l5Enabled;
    private boolean l6Enabled;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean isL1Enabled() { return l1Enabled; }
    public void setL1Enabled(boolean l1Enabled) { this.l1Enabled = l1Enabled; }
    public boolean isL2Enabled() { return l2Enabled; }
    public void setL2Enabled(boolean l2Enabled) { this.l2Enabled = l2Enabled; }
    public boolean isL3Enabled() { return l3Enabled; }
    public void setL3Enabled(boolean l3Enabled) { this.l3Enabled = l3Enabled; }
    public boolean isL4Enabled() { return l4Enabled; }
    public void setL4Enabled(boolean l4Enabled) { this.l4Enabled = l4Enabled; }
    public boolean isL5Enabled() { return l5Enabled; }
    public void setL5Enabled(boolean l5Enabled) { this.l5Enabled = l5Enabled; }
    public boolean isL6Enabled() { return l6Enabled; }
    public void setL6Enabled(boolean l6Enabled) { this.l6Enabled = l6Enabled; }
}
