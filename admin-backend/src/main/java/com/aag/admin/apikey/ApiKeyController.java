package com.aag.admin.apikey;

import com.aag.admin.common.NotFoundException;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/api-keys")
public class ApiKeyController {

    private final ApiKeyRepository repository;
    private final SecureRandom random = new SecureRandom();

    public ApiKeyController(ApiKeyRepository repository) {
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> issue(@Valid @RequestBody ApiKeyRequest request) {
        String plainKey = generatePlainKey();
        String hash = sha256(plainKey);

        ApiKey apiKey = new ApiKey();
        apiKey.setName(request.getName());
        apiKey.setOwner(request.getOwner());
        apiKey.setKeyHash(hash);
        apiKey.setRevoked(false);
        ApiKey saved = repository.save(apiKey);

        Map<String, Object> response = toResponse(saved);
        response.put("plainKey", plainKey);
        return ResponseEntity.created(URI.create("/api/v1/api-keys/" + saved.getId())).body(response);
    }

    @GetMapping
    public List<Map<String, Object>> list() {
        return repository.findAll().stream().map(this::toResponse).toList();
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        ApiKey apiKey = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("api key not found: " + id));
        return toResponse(apiKey);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(@PathVariable Long id) {
        ApiKey apiKey = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("api key not found: " + id));
        apiKey.setRevoked(true);
        repository.save(apiKey);
        return ResponseEntity.noContent().build();
    }

    private Map<String, Object> toResponse(ApiKey apiKey) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", apiKey.getId());
        map.put("name", apiKey.getName());
        map.put("owner", apiKey.getOwner());
        map.put("revoked", apiKey.isRevoked());
        map.put("createdAt", apiKey.getCreatedAt());
        return map;
    }

    private String generatePlainKey() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return "aag_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
