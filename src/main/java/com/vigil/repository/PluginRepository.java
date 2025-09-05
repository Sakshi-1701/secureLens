package com.vigil.repository;

import com.vigil.domain.Plugin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PluginRepository extends JpaRepository<Plugin, Long> {
}


