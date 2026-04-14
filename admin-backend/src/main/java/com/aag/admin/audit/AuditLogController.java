package com.aag.admin.audit;

import com.aag.admin.common.BadRequestException;
import com.aag.admin.common.NotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit-logs")
public class AuditLogController {

    private final AuditLogRepository repository;

    public AuditLogController(AuditLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(defaultValue = "0") int page,
                                    @RequestParam(defaultValue = "20") int size,
                                    @RequestParam(required = false) String from,
                                    @RequestParam(required = false) String to) {
        Page<AuditLog> result;
        if (from != null && to != null) {
            Instant fromInstant;
            Instant toInstant;
            try {
                fromInstant = Instant.parse(from);
                toInstant = Instant.parse(to);
            } catch (DateTimeParseException ex) {
                throw new BadRequestException("invalid date format");
            }
            if (fromInstant.isAfter(toInstant)) {
                throw new BadRequestException("'from' must be before 'to'");
            }
            result = repository.findByOccurredAtBetween(fromInstant, toInstant, PageRequest.of(page, size));
        } else {
            result = repository.findAll(PageRequest.of(page, size));
        }
        Map<String, Object> body = new HashMap<>();
        body.put("content", result.getContent().stream().map(this::toResponse).toList());
        body.put("totalElements", result.getTotalElements());
        body.put("totalPages", result.getTotalPages());
        body.put("page", result.getNumber());
        body.put("size", result.getSize());
        return body;
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        AuditLog log = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("audit log not found: " + id));
        return toResponse(log);
    }

    private Map<String, Object> toResponse(AuditLog log) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", log.getId());
        map.put("actor", log.getActor());
        map.put("action", log.getAction());
        map.put("resource", log.getResource());
        map.put("details", log.getDetails());
        map.put("occurredAt", log.getOccurredAt());
        return map;
    }
}
