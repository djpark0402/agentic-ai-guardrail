package com.aag.admin.audit;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt = Instant.now();

    @Enumerated(EnumType.STRING)
    @Column(name = "action_id", nullable = false, length = 32)
    private ActorType actionId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Action action;

    @Column(nullable = false)
    private boolean success;

    @Column(length = 500)
    private String detail;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Instant getOccurredAt() { return occurredAt; }
    public void setOccurredAt(Instant occurredAt) { this.occurredAt = occurredAt; }
    public ActorType getActionId() { return actionId; }
    public void setActionId(ActorType actionId) { this.actionId = actionId; }
    public Action getAction() { return action; }
    public void setAction(Action action) { this.action = action; }
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
}
