package com.aag.admin.policy;

import com.aag.admin.common.NotFoundException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/policies")
public class PolicyController {

    private final PolicyRepository repository;

    public PolicyController(PolicyRepository repository) {
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody PolicyRequest request) {
        Policy policy = new Policy();
        policy.setName(request.getName());
        policy.setDescription(request.getDescription());
        policy.setRuleType(request.getRuleType());
        policy.setPattern(request.getPattern());
        policy.setEnabled(request.isEnabled());
        Policy saved = repository.save(policy);
        return ResponseEntity.created(URI.create("/api/v1/policies/" + saved.getId()))
                .body(toResponse(saved));
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(defaultValue = "0") int page,
                                    @RequestParam(defaultValue = "20") int size) {
        Page<Policy> result = repository.findAll(PageRequest.of(page, size));
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
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        return toResponse(policy);
    }

    @PutMapping("/{id}")
    public Map<String, Object> update(@PathVariable Long id, @Valid @RequestBody PolicyRequest request) {
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        policy.setName(request.getName());
        policy.setDescription(request.getDescription());
        policy.setRuleType(request.getRuleType());
        policy.setPattern(request.getPattern());
        policy.setEnabled(request.isEnabled());
        policy.setUpdatedAt(Instant.now());
        return toResponse(repository.save(policy));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        if (!repository.existsById(id)) {
            throw new NotFoundException("policy not found: " + id);
        }
        repository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private Map<String, Object> toResponse(Policy policy) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", policy.getId());
        map.put("name", policy.getName());
        map.put("description", policy.getDescription());
        map.put("ruleType", policy.getRuleType());
        map.put("pattern", policy.getPattern());
        map.put("enabled", policy.isEnabled());
        map.put("createdAt", policy.getCreatedAt());
        map.put("updatedAt", policy.getUpdatedAt());
        return map;
    }
}
