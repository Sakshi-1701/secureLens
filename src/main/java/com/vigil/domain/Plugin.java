package com.vigil.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.OffsetDateTime;

@Entity
@Table(name = "plugins")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Plugin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "plugin_name", nullable = false)
    private String pluginName;

    @Column(name = "upload_timestamp", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private OffsetDateTime uploadTimestamp = OffsetDateTime.now();

    @Column(name = "source_type", nullable = false, length = 50)
    private String sourceType; // ZIP or GIT_URL

    @Column(name = "source_location", nullable = false, columnDefinition = "TEXT")
    private String sourceLocation; // server file path or Git URL

    @Column(name = "scan_status", length = 50)
    private String scanStatus = "PENDING"; // PENDING, SCANNING, COMPLETED, FAILED
}


