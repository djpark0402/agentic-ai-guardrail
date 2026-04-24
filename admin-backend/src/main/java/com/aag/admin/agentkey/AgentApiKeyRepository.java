package com.aag.admin.agentkey;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AgentApiKeyRepository extends JpaRepository<AgentApiKey, Long> {

    Optional<AgentApiKey> findByApiKeyHash(String apiKeyHash);

    List<AgentApiKey> findAllByOrderByCreatedAtDesc();
}
