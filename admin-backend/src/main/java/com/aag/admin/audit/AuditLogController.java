package com.aag.admin.audit;

import com.aag.admin.common.BadRequestException;
import com.aag.admin.common.NotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Tag(name = "Audit Log", description = "감사 로그 조회 API")
@RestController
@RequestMapping("/api/v1/audit-logs")
public class AuditLogController {

    private static final List<String> ALLOWED_SORT_FIELDS = List.of("occurredAt", "action", "actionId", "success");

    private final AuditLogRepository repository;

    public AuditLogController(AuditLogRepository repository) {
        this.repository = repository;
    }

    @Operation(summary = "감사 로그 목록 조회", description = "필터 + 정렬 + 페이지네이션 지원")
    @GetMapping
    public Map<String, Object> list(@ModelAttribute AuditLogSearchRequest request) {
        Instant fromInstant = parseInstant(request.getFrom(), "from");
        Instant toInstant = parseInstant(request.getTo(), "to");
        if (fromInstant != null && toInstant != null && fromInstant.isAfter(toInstant)) {
            throw new BadRequestException("'from' must be before 'to'");
        }

        ActorType actorType = parseActorType(request.getActionId());
        Action actionEnum = parseAction(request.getAction());

        String sortField = ALLOWED_SORT_FIELDS.contains(request.getSort()) ? request.getSort() : "occurredAt";
        Sort.Direction dir = "asc".equalsIgnoreCase(request.getDirection()) ? Sort.Direction.ASC : Sort.Direction.DESC;

        Specification<AuditLog> spec = buildSpec(fromInstant, toInstant, actorType, actionEnum, request.getSuccess());
        Page<AuditLog> result = repository.findAll(
                spec,
                PageRequest.of(request.getPage(), request.getSize(), Sort.by(dir, sortField)));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("content", result.getContent().stream().map(this::toResponse).toList());
        body.put("page", result.getNumber());
        body.put("size", result.getSize());
        body.put("totalElements", result.getTotalElements());
        body.put("totalPages", result.getTotalPages());
        return body;
    }

    @Operation(summary = "감사 로그 단건 조회")
    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        AuditLog log = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("audit log not found: " + id));
        return toResponse(log);
    }

    private Specification<AuditLog> buildSpec(Instant from, Instant to, ActorType actorType, Action action, Boolean success) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("occurredAt"), to));
            }
            if (actorType != null) {
                predicates.add(cb.equal(root.get("actionId"), actorType));
            }
            if (action != null) {
                predicates.add(cb.equal(root.get("action"), action));
            }
            if (success != null) {
                predicates.add(cb.equal(root.get("success"), success));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Instant parseInstant(String value, String field) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw new BadRequestException("invalid date format: " + field);
        }
    }

    private ActorType parseActorType(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return ActorType.stringValueOf(value);
        } catch (AssertionError ex) {
            throw new BadRequestException("invalid actionId");
        }
    }

    private Action parseAction(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Action.stringValueOf(value);
        } catch (AssertionError ex) {
            throw new BadRequestException("invalid action");
        }
    }

    private Map<String, Object> toResponse(AuditLog log) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", log.getId());
        map.put("occurredAt", log.getOccurredAt());
        map.put("actionId", log.getActionId());
        map.put("action", log.getAction());
        map.put("success", log.isSuccess());
        map.put("detail", log.getDetail());
        return map;
    }
}
