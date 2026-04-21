package com.aag.admin.apikey;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface InternalApiKeyRepository extends JpaRepository<InternalApiKey, Long> {

    Optional<InternalApiKey> findByKeyHash(String keyHash);

    List<InternalApiKey> findAllByOrderByCreatedAtDesc();
}
