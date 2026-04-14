package com.aag.admin.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    Page<AuditLog> findByOccurredAtBetween(Instant from, Instant to, Pageable pageable);
}
