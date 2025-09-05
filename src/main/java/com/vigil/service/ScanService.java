package com.vigil.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vigil.domain.Plugin;
import com.vigil.repository.PluginRepository;
import com.vigil.repository.ScanResultRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanService {

    private final PluginRepository pluginRepository;
    private final OpenRouterScanService openRouterScanService;

    @Value("${vigil.storage.base-dir}")
    private String baseDir;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Plugin saveZipUpload(String pluginName, MultipartFile zipFile) throws IOException {
        log.info("Starting ZIP upload for plugin: {}", pluginName);
        log.info("File details - Name: {}, Size: {} bytes", zipFile.getOriginalFilename(), zipFile.getSize());
        
        Path pluginDir = ensurePluginDir();
        log.info("Plugin directory: {}", pluginDir);
        
        String storedName = UUID.randomUUID() + "-" + zipFile.getOriginalFilename();
        Path storedPath = pluginDir.resolve(storedName);
        log.info("Storing file at: {}", storedPath);
        
        try (FileOutputStream out = new FileOutputStream(storedPath.toFile())) {
            out.write(zipFile.getBytes());
            log.info("File written successfully to: {}", storedPath);
        }
        
        Plugin plugin = Plugin.builder()
                .pluginName(pluginName)
                .uploadTimestamp(OffsetDateTime.now())
                .sourceType("ZIP")
                .sourceLocation(storedPath.toString())
                .scanStatus("PENDING")
                .build();
        
        Plugin savedPlugin = pluginRepository.save(plugin);
        log.info("Plugin saved with ID: {}", savedPlugin.getId());
        return savedPlugin;
    }

    public Plugin saveGitUrl(String pluginName, String gitUrl) {
        log.info("Saving Git URL for plugin: {} - URL: {}", pluginName, gitUrl);
        Plugin plugin = Plugin.builder()
                .pluginName(pluginName)
                .uploadTimestamp(OffsetDateTime.now())
                .sourceType("GIT_URL")
                .sourceLocation(gitUrl)
                .scanStatus("PENDING")
                .build();
        Plugin savedPlugin = pluginRepository.save(plugin);
        log.info("Git URL plugin saved with ID: {}", savedPlugin.getId());
        return savedPlugin;
    }

    private Path ensurePluginDir() throws IOException {
        log.info("Ensuring plugin directory exists at base: {}", baseDir);
        Path dir = Paths.get(baseDir).resolve("plugins");
        Files.createDirectories(dir);
        log.info("Plugin directory created/verified at: {}", dir);
        return dir;
    }

    @Async
    @Transactional
    public void startScan(Long pluginId) {
        log.info("=== STARTING OPENROUTER SCAN FOR PLUGIN ID: {} ===", pluginId);
        try {
            Plugin plugin = pluginRepository.findById(pluginId).orElseThrow(() -> {
                log.error("Plugin not found with ID: {}", pluginId);
                return new RuntimeException("Plugin not found");
            });
            log.info("Found plugin: {} - Type: {} - Location: {}", 
                    plugin.getPluginName(), plugin.getSourceType(), plugin.getSourceLocation());
            
            plugin.setScanStatus("SCANNING");
            pluginRepository.save(plugin);
            log.info("Plugin status updated to SCANNING");

            try {
                // Use OpenRouter for vulnerability scanning
                openRouterScanService.scanPlugin(plugin);
                
                plugin.setScanStatus("COMPLETED");
                pluginRepository.save(plugin);
                log.info("=== OPENROUTER SCAN COMPLETED SUCCESSFULLY FOR PLUGIN ID: {} ===", pluginId);
                
            } catch (Exception ex) {
                log.error("Exception during OpenRouter scan for plugin ID: {}", pluginId, ex);
                plugin.setScanStatus("FAILED");
                pluginRepository.save(plugin);
                log.error("=== OPENROUTER SCAN FAILED FOR PLUGIN ID: {} ===", pluginId);
            }
        } catch (Exception ex) {
            log.error("Critical error in startScan for plugin ID: {}", pluginId, ex);
        }
    }

}


