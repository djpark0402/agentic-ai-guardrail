package com.aag.admin.policy;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "policies")
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(length = 500)
    private String description;

    @Column(name = "l1_enabled", nullable = false)
    private boolean l1Enabled;

    @Column(name = "l2_enabled", nullable = false)
    private boolean l2Enabled;

    @Column(name = "l3_enabled", nullable = false)
    private boolean l3Enabled;

    @Column(name = "l4_enabled", nullable = false)
    private boolean l4Enabled;

    @Column(name = "l5_enabled", nullable = false)
    private boolean l5Enabled;

    @Column(name = "l6_enabled", nullable = false)
    private boolean l6Enabled;

    @Column(name = "outbound_enabled", nullable = false, columnDefinition = "BOOLEAN NOT NULL DEFAULT FALSE")
    private boolean outboundEnabled;

    @Column(name = "is_use", nullable = false)
    private boolean isUse;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
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
    public boolean isOutboundEnabled() { return outboundEnabled; }
    public void setOutboundEnabled(boolean outboundEnabled) { this.outboundEnabled = outboundEnabled; }
    public boolean isUse() { return isUse; }
    public void setUse(boolean use) { this.isUse = use; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
