package com.vigil.repository;

import com.vigil.domain.ScanResult;
import com.vigil.domain.Plugin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByPlugin(Plugin plugin);
}


