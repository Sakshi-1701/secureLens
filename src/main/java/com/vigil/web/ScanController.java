package com.vigil.web;

import com.vigil.domain.Plugin;
import com.vigil.domain.ScanResult;
import com.vigil.repository.PluginRepository;
import com.vigil.repository.ScanResultRepository;
import com.vigil.service.EmailService;
import com.vigil.service.PdfReportService;
import com.vigil.service.ScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

import static org.eclipse.jgit.revwalk.filter.SubStringRevFilter.safe;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class ScanController {

    private final ScanService scanService;
    private final PluginRepository pluginRepository;
    private final ScanResultRepository scanResultRepository;
    private final EmailService emailService;
    private final PdfReportService pdfReportService;

    /** Upload a ZIP plugin */
    @PostMapping(value = "/upload-plugin", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadPlugin(@RequestParam("pluginName") String pluginName,
                                         @RequestParam("file") MultipartFile zipFile) {
        log.info("Received ZIP upload request - Plugin: {}, File: {}, Size: {}", 
                pluginName, zipFile.getOriginalFilename(), zipFile.getSize());
        try {
            if (zipFile.isEmpty()) {
                log.warn("Empty file received for plugin: {}", pluginName);
                return ResponseEntity.badRequest().body("File is empty");
            }
            if (!zipFile.getOriginalFilename().toLowerCase().endsWith(".zip")) {
                log.warn("Non-ZIP file received: {}", zipFile.getOriginalFilename());
                return ResponseEntity.badRequest().body("File must be a ZIP file");
            }
            Plugin plugin = scanService.saveZipUpload(pluginName, zipFile);
            log.info("ZIP upload successful - Plugin ID: {}", plugin.getId());
            return ResponseEntity.ok(plugin);
        } catch (Exception e) {
            log.error("ZIP upload failed for plugin: {}", pluginName, e);
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }

    /** Save a Git URL */
    @PostMapping("/upload-plugin/git")
    public Plugin uploadGit(@RequestParam("pluginName") String pluginName,
                            @RequestParam("gitUrl") String gitUrl) {
        log.info("Received Git URL request - Plugin: {}, URL: {}", pluginName, gitUrl);
        Plugin plugin = scanService.saveGitUrl(pluginName, gitUrl);
        log.info("Git URL saved successfully - Plugin ID: {}", plugin.getId());
        return plugin;
    }

    /** Trigger scan */
    @PostMapping("/scan-plugin/{pluginId}")
    public ResponseEntity<?> scanPlugin(@PathVariable Long pluginId) {
        log.info("Received scan request for plugin ID: {}", pluginId);
        scanService.startScan(pluginId);
        log.info("Scan triggered for plugin ID: {}", pluginId);
        return ResponseEntity.accepted().build();
    }

    /** Get scan status */
    @GetMapping("/scan-status/{pluginId}")
    public ResponseEntity<String> status(@PathVariable Long pluginId) {
        return pluginRepository.findById(pluginId)
                .map(p -> ResponseEntity.ok(p.getScanStatus()))
                .orElse(ResponseEntity.notFound().build());
    }

    /** Get scan results */
    @GetMapping("/scan-results/{pluginId}")
    public List<ScanResult> results(@PathVariable Long pluginId) {
        Plugin plugin = pluginRepository.findById(pluginId).orElseThrow();
        return scanResultRepository.findByPlugin(plugin);
    }

    /** List all reports (plugins) */
    @GetMapping("/reports")
    public List<Plugin> reports() {
        return pluginRepository.findAll();
    }

    /** Send report via email */
    @PostMapping("/send-report/{pluginId}")
    public ResponseEntity<?> sendReport(@PathVariable Long pluginId,
                                        @RequestParam String to) {
        log.info("Sending PDF report via email for plugin ID: {} to: {}", pluginId, to);
        try {
            Plugin plugin = pluginRepository.findById(pluginId).orElseThrow(() -> {
                log.error("Plugin not found with ID: {}", pluginId);
                return new RuntimeException("Plugin not found");
            });
            
            List<ScanResult> results = scanResultRepository.findByPlugin(plugin);
            log.info("Found {} vulnerabilities for plugin: {}", results.size(), plugin.getPluginName());
            
            // Generate PDF report
            byte[] pdfBytes = pdfReportService.generatePdfReport(plugin, results);
            
            // Email configuration
            String subject = "Security Scan Report - " + pluginId;
            String body = "<html><body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>" +
                    "<p>Hello,</p>" +
                    "<br/>" +
                    "<p>Please find attached your latest <strong>Security Scan Report</strong>.</p>" +
                    "<br/>" +
                    "<p>It highlights vulnerabilities detected during the scan along with suggested fixes.</p>" +
                    "<br/>" +
                    "<hr style='border: none; border-top: 1px solid #ccc; margin: 20px 0;'/>" +
                    "<p><strong>Thanks & Regards,</strong><br/>" +
                    "Team miniOrange Null-Pointers 🚀</p>" +
                    "</body></html>";
            String attachmentName = pluginId + "-report.pdf";
            
            // Send email with PDF attachment
            emailService.sendPdfAttachment(to, subject, body, pdfBytes, attachmentName);
            
            log.info("PDF report sent successfully via email for plugin ID: {}", pluginId);
            return ResponseEntity.ok().build();
            
        } catch (Exception e) {
            log.error("Failed to send PDF report via email for plugin ID: {}", pluginId, e);
            return ResponseEntity.status(500).body("Failed to send email: " + e.getMessage());
        }
    }

    /** Delete report */
    @DeleteMapping("/delete-report/{pluginId}")
    public ResponseEntity<?> deleteReport(@PathVariable Long pluginId) {
        pluginRepository.deleteById(pluginId);
        return ResponseEntity.noContent().build();
    }

    /** Download PDF report */
    @GetMapping("/download-report/{pluginId}")
    public ResponseEntity<byte[]> downloadPdfReport(@PathVariable Long pluginId) {
        log.info("Generating PDF report for plugin ID: {}", pluginId);
        try {
            Plugin plugin = pluginRepository.findById(pluginId).orElseThrow(() -> {
                log.error("Plugin not found with ID: {}", pluginId);
                return new RuntimeException("Plugin not found");
            });
            
            List<ScanResult> results = scanResultRepository.findByPlugin(plugin);
            log.info("Found {} vulnerabilities for plugin: {}", results.size(), plugin.getPluginName());
            
            byte[] pdfBytes = pdfReportService.generatePdfReport(plugin, results);
            
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + pluginId + "-report.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, "application/pdf");
            
            log.info("PDF report generated successfully for plugin ID: {}", pluginId);
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(pdfBytes);
                    
        } catch (Exception e) {
            log.error("Failed to generate PDF report for plugin ID: {}", pluginId, e);
            return ResponseEntity.status(500).build();
        }
    }


    private String buildHtmlReport(Plugin plugin, List<ScanResult> results) {
        String rows = results.stream().map(r -> "<tr>" +
                "<td>" + safe(r.getSeverity()) + "</td>" +
                "<td>" + safe(String.valueOf(r.getCvssScore())) + "</td>" +
                "<td>" + safe(r.getVulnerabilityId()) + "</td>" +
                "<td>" + safe(r.getVulnerabilityName()) + "</td>" +
                "<td><pre>" + safe(r.getDescription()) + "</pre></td>" +
                "<td><pre>" + safe(r.getAiSuggestion()) + "</pre></td>" +
                "</tr>").collect(Collectors.joining());
        return "<html><body>" +
                "<h2>Vigil Scan Report - " + plugin.getPluginName() + "</h2>" +
                "<table border='1' cellspacing='0' cellpadding='6'>" +
                "<thead><tr><th>Severity</th><th>CVSS</th><th>ID</th><th>Name</th><th>Description</th><th>AI Suggestion</th></tr></thead>" +
                "<tbody>" + rows + "</tbody>" +
                "</table></body></html>";
    }
}


