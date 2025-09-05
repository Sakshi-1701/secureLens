package com.vigil.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "scan_results")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "plugin_id", nullable = false)
    private Plugin plugin;

    @Column(name = "severity", nullable = false, length = 50)
    private String severity; // HIGH, MEDIUM, LOW, INFO

    @Column(name = "vulnerability_id", length = 100)
    private String vulnerabilityId; // e.g., CVE-2023-12345

    @Column(name = "vulnerability_name", nullable = false, columnDefinition = "TEXT")
    private String vulnerabilityName;

    @Column(name = "cvss_score")
    private Double cvssScore;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "fix_suggestion", columnDefinition = "TEXT")
    private String fixSuggestion;

    @Column(name = "ai_suggestion", columnDefinition = "TEXT")
    private String aiSuggestion; // NEW: AI-generated suggestion
}


