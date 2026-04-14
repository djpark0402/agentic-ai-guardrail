package com.aag.admin.apikey;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {
}
