package com.aag.admin.policy;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface PolicyRepository extends JpaRepository<Policy, Long> {

    Optional<Policy> findByIsUseTrue();

    List<Policy> findAllByOrderByCreatedAtAsc();

    @Modifying
    @Query("update Policy p set p.isUse = false where p.isUse = true and p.id <> :excludeId")
    int clearActiveExcept(Long excludeId);
}
