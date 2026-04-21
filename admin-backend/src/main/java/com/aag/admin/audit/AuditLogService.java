package com.aag.admin.audit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuditLogService {

    private final AuditLogRepository repository;

    public AuditLogService(AuditLogRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(ActorType actorType, Action action, boolean success, String detail) {
        AuditLog log = new AuditLog();
        log.setOccurredAt(Instant.now());
        log.setActionId(actorType);
        log.setAction(action);
        log.setSuccess(success);
        log.setDetail(detail);
        repository.save(log);
    }
}
