package com.vigil.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vigil.domain.Plugin;
import com.vigil.domain.ScanResult;
import com.vigil.repository.ScanResultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
@Slf4j
public class OpenRouterScanService {

    private final ScanResultRepository scanResultRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate;

    @Value("${openrouter.api.key}")
    private String apiKey;

    @Value("${openrouter.base.url}")
    private String baseUrl;

    @Value("${openrouter.timeout.seconds:30}")
    private int timeoutSeconds;

    public OpenRouterScanService(ScanResultRepository scanResultRepository) {
        this.scanResultRepository = scanResultRepository;
        this.restTemplate = createRestTemplate();
    }

    private RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds));
        factory.setReadTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds));
        
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(factory);
        return template;
    }

    public void scanPlugin(Plugin plugin) {
        log.info("Starting OpenRouter scan for plugin: {} - Type: {}", plugin.getPluginName(), plugin.getSourceType());
        
        try {
            List<ScanResult> vulnerabilities = new ArrayList<>();
            
            if ("ZIP".equalsIgnoreCase(plugin.getSourceType())) {
                vulnerabilities = scanZipFile(plugin);
            } else {
                vulnerabilities = scanGitRepository(plugin);
            }
            
            // Save all vulnerabilities
            for (ScanResult result : vulnerabilities) {
                scanResultRepository.save(result);
            }
            
            log.info("OpenRouter scan completed for plugin: {} - Found {} vulnerabilities", 
                    plugin.getPluginName(), vulnerabilities.size());
            
        } catch (Exception e) {
            log.error("OpenRouter scan failed for plugin: {}", plugin.getPluginName(), e);
            throw new RuntimeException("Scan failed: " + e.getMessage(), e);
        }
    }

    private List<ScanResult> scanZipFile(Plugin plugin) throws IOException {
        log.info("Scanning ZIP file: {}", plugin.getSourceLocation());
        
        File zipFile = new File(plugin.getSourceLocation());
        if (!zipFile.exists()) {
            throw new IOException("ZIP file not found: " + plugin.getSourceLocation());
        }
        
        // Extract ZIP and collect all relevant file contents
        String extractPath = extractZipFile(zipFile);
        StringBuilder allContent = new StringBuilder();
        
        try {
            List<Path> filesToScan = findRelevantFiles(Paths.get(extractPath));
            log.info("Found {} files to scan in ZIP", filesToScan.size());
            
            // Collect all file contents into a single string
            for (Path filePath : filesToScan) {
                try {
                    String fileContent = Files.readString(filePath);
                    String relativePath = Paths.get(extractPath).relativize(filePath).toString();
                    
                    allContent.append("=== FILE: ").append(relativePath).append(" ===\n");
                    allContent.append(fileContent).append("\n\n");
                    
                    log.debug("Collected content from file: {}", relativePath);
                    
                } catch (Exception e) {
                    log.warn("Failed to read file: {}", filePath, e);
                }
            }
            
            // Send all content to OpenRouter in one request
            if (allContent.length() > 0) {
                log.info("Sending {} characters of code to OpenRouter for analysis", allContent.length());
                
                String prompt = String.format(
                    "Analyze this codebase for security vulnerabilities:\n\n%s\n\n" +
                    "Look for common security issues like: SQL injection, XSS, CSRF, hardcoded secrets, " +
                    "insecure configurations, vulnerable code patterns, authentication issues, authorization flaws, etc. " +
                    "For each vulnerability found, provide specific file names, line numbers, and exact code that needs to be changed. " +
                    "\n\nIMPORTANT: You MUST respond with ONLY valid JSON. Do not include any text before or after the JSON. " +
                    "The response must be a JSON array of vulnerabilities with this exact structure:\n" +
                    "[\n" +
                    "  {\n" +
                    "    \"name\": \"Vulnerability Name\",\n" +
                    "    \"severity\": \"HIGH\",\n" +
                    "    \"description\": \"Description of the vulnerability\",\n" +
                    "    \"cvss_score\": 8.5,\n" +
                    "    \"file_path\": \"path/to/file.java\",\n" +
                    "    \"line_number\": \"45\",\n" +
                    "    \"vulnerable_code\": \"String query = \\\"SELECT * FROM users WHERE username = '\\\" + username + \\\"'\\\";\",\n" +
                    "    \"fixed_code\": \"String query = \\\"SELECT * FROM users WHERE username = ?\\\";\",\n" +
                    "    \"fix_suggestion\": \"Use parameterized queries\",\n" +
                    "    \"ai_suggestion\": \"Detailed explanation of the fix\"\n" +
                    "  }\n" +
                    "]\n\n" +
                    "If no vulnerabilities are found, return an empty array: []",
                    allContent.toString()
                );
                
                List<ScanResult> results = callOpenRouter(prompt, plugin);
                log.info("OpenRouter analysis completed. Found {} vulnerabilities", results.size());
                return results;
            } else {
                log.warn("No content found to analyze in ZIP file");
            }
            
        } finally {
            // Clean up extracted files
            cleanupExtractedFiles(extractPath);
        }
        
        return new ArrayList<>();
    }

    private List<ScanResult> scanGitRepository(Plugin plugin) {
        log.info("Scanning Git repository: {}", plugin.getSourceLocation());
        
        // For Git repositories, we'll analyze the URL and provide a general analysis
        // In a real implementation, you would clone the repository and scan files
        String prompt = String.format(
            "Analyze this Git repository URL for potential security vulnerabilities: %s. " +
            "Look for common security issues like: outdated dependencies, " +
            "hardcoded secrets, insecure configurations, vulnerable code patterns, SQL injection, XSS, CSRF, etc. " +
            "Provide a general security assessment based on the repository URL and common patterns. " +
            "\n\nIMPORTANT: You MUST respond with ONLY valid JSON. Do not include any text before or after the JSON. " +
            "The response must be a JSON array of vulnerabilities with this exact structure:\n" +
            "[\n" +
            "  {\n" +
            "    \"name\": \"Vulnerability Name\",\n" +
            "    \"severity\": \"HIGH\",\n" +
            "    \"description\": \"Description of the vulnerability\",\n" +
            "    \"cvss_score\": 8.5,\n" +
            "    \"file_path\": \"path/to/file.java\",\n" +
            "    \"line_number\": \"45\",\n" +
            "    \"vulnerable_code\": \"String query = \\\"SELECT * FROM users WHERE username = '\\\" + username + \\\"'\\\";\",\n" +
            "    \"fixed_code\": \"String query = \\\"SELECT * FROM users WHERE username = ?\\\";\",\n" +
            "    \"fix_suggestion\": \"Use parameterized queries\",\n" +
            "    \"ai_suggestion\": \"Detailed explanation of the fix\"\n" +
            "  }\n" +
            "]\n\n" +
            "If no vulnerabilities are found, return an empty array: []",
            plugin.getSourceLocation()
        );
        
        return callOpenRouter(prompt, plugin);
    }

    private String extractZipFile(File zipFile) throws IOException {
        // Create temporary directory for extraction
        Path tempDir = Files.createTempDirectory("vigil-scan-");
        String extractPath = tempDir.toString();
        
        log.info("Extracting ZIP file {} to: {}", zipFile.getName(), extractPath);
        
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry = zipIn.getNextEntry();
            int fileCount = 0;
            final int MAX_FILES = 1000; // Prevent ZIP bombs
            
            while (entry != null && fileCount < MAX_FILES) {
                String entryName = entry.getName();
                
                // Security check: prevent directory traversal attacks
                if (entryName.contains("..") || entryName.startsWith("/")) {
                    log.warn("Skipping potentially malicious entry: {}", entryName);
                    zipIn.closeEntry();
                    entry = zipIn.getNextEntry();
                    continue;
                }
                
                String filePath = extractPath + File.separator + entryName;
                Path targetPath = Paths.get(filePath);
                
                // Ensure the target path is within the extraction directory
                if (!targetPath.normalize().startsWith(Paths.get(extractPath).normalize())) {
                    log.warn("Skipping entry outside extraction directory: {}", entryName);
                    zipIn.closeEntry();
                    entry = zipIn.getNextEntry();
                    continue;
                }
                
                if (!entry.isDirectory()) {
                    // Create parent directories if they don't exist
                    File file = new File(filePath);
                    File parentDir = file.getParentFile();
                    if (parentDir != null && !parentDir.exists()) {
                        parentDir.mkdirs();
                    }
                    
                    // Extract file
                    try (var fos = Files.newOutputStream(targetPath)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = zipIn.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                    
                    log.debug("Extracted file: {}", entryName);
                    fileCount++;
                } else {
                    // Create directory
                    File dir = new File(filePath);
                    if (!dir.exists()) {
                        dir.mkdirs();
                    }
                }
                
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            
            if (fileCount >= MAX_FILES) {
                log.warn("ZIP extraction stopped at {} files to prevent ZIP bomb", MAX_FILES);
            }
            log.info("ZIP extraction completed. Extracted {} files to: {}", fileCount, extractPath);

        }
        
        return extractPath;
    }

    private List<Path> findRelevantFiles(Path directory) throws IOException {
        List<Path> relevantFiles = new ArrayList<>();
        
        try (Stream<Path> paths = Files.walk(directory)) {
            paths.filter(Files::isRegularFile)
                 .filter(this::isRelevantFile)
                 .forEach(relevantFiles::add);
        }
        
        return relevantFiles;
    }

    private boolean isRelevantFile(Path file) {
        String fileName = file.getFileName().toString().toLowerCase();
        String extension = getFileExtension(fileName);
        
        // Include common source code and configuration files
        return extension.matches("(java|js|ts|jsx|tsx|py|php|go|cs|cpp|c|h|xml|json|yml|yaml|properties|conf|config|sql|sh|bat|ps1)") ||
               fileName.matches("(pom\\.xml|package\\.json|requirements\\.txt|Dockerfile|docker-compose\\.yml|Makefile|README\\.md)");
    }

    private String getFileExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        return lastDot > 0 ? fileName.substring(lastDot + 1) : "";
    }

    private List<ScanResult> scanFileContent(String fileContent, String filePath, Plugin plugin) {
        try {
            // Limit file content size to avoid token limits
            if (fileContent.length() > 10000) {
                fileContent = fileContent.substring(0, 10000) + "\n... [Content truncated for analysis]";
            }
            
            String prompt = String.format(
                "Analyze this source code file for security vulnerabilities:\n\n" +
                "File: %s\n" +
                "Content:\n%s\n\n" +
                "Look for common security issues like: SQL injection, XSS, CSRF, hardcoded secrets, " +
                "insecure configurations, vulnerable code patterns, authentication issues, authorization flaws, etc. " +
                "For each vulnerability found, provide specific line numbers and exact code that needs to be changed. " +
                "Return results in JSON format with array of vulnerabilities, each containing: " +
                "name, severity (HIGH/MEDIUM/LOW/INFO), description, cvss_score (0.0-10.0), file_path, line_number, " +
                "vulnerable_code, fixed_code, fix_suggestion, ai_suggestion.",
                filePath, fileContent
            );
            
            return callOpenRouter(prompt, plugin);
            
        } catch (Exception e) {
            log.warn("Failed to scan file content: {}", filePath, e);
            return new ArrayList<>();
        }
    }

    private void cleanupExtractedFiles(String extractPath) {
        try {
            Path path = Paths.get(extractPath);
            if (Files.exists(path)) {
                Files.walk(path)
                     .sorted(Comparator.reverseOrder())
                     .map(Path::toFile)
                     .forEach(File::delete);
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup extracted files: {}", extractPath, e);
        }
    }

    private List<ScanResult> callOpenRouter(String prompt, Plugin plugin) {
        // Try multiple models in case one is not available
        String[] models = {
            "meta-llama/llama-3.1-8b-instruct",
            "meta-llama/llama-3.1-70b-instruct", 
            "openai/gpt-3.5-turbo",
            "anthropic/claude-3-haiku"
        };
        
        for (String model : models) {
            try {
                log.info("Calling OpenRouter API with model: {}", model);
                
                // Validate API key
                if (apiKey == null || apiKey.trim().isEmpty()) {
                    throw new RuntimeException("OpenRouter API key is not configured");
                }
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", "Bearer " + apiKey);
            headers.set("HTTP-Referer", "https://vigil-security-scanner.com");
            headers.set("X-Title", "Vigil Security Scanner");

            Map<String, Object> requestBody = new HashMap<>();
                requestBody.put("model", model);
            requestBody.put("messages", Arrays.asList(
                Map.of("role", "user", "content", prompt)
            ));
            requestBody.put("max_tokens", 4000);
            requestBody.put("temperature", 0.1);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            String url = baseUrl + "/chat/completions";
            log.debug("OpenRouter API URL: {}", url);
            
            Map<String, Object> response = restTemplate.postForObject(url, entity, Map.class);
            
            if (response == null) {
                    log.warn("OpenRouter returned null response for model: {}", model);
                    continue; // Try next model
            }
            
            String content = extractContentFromResponse(response);
                log.info("OpenRouter response received (length: {}) for model: {}", content.length(), model);
            log.debug("OpenRouter response content: {}", content);
            
            return parseVulnerabilitiesFromResponse(content, plugin);
            
            } catch (RestClientException e) {
                log.warn("OpenRouter API call failed for model {}: {}", model, e.getMessage());
                if (e.getMessage().contains("404")) {
                    continue; // Try next model
                } else {
                    throw new RuntimeException("Failed to call OpenRouter API: " + e.getMessage(), e);
                }
        } catch (Exception e) {
                log.warn("Unexpected error with model {}: {}", model, e.getMessage());
                continue; // Try next model
            }
        }
        
        // If all models failed
        throw new RuntimeException("All OpenRouter models failed. Please check your API key and available models.");
    }

    private String extractContentFromResponse(Map<String, Object> response) {
        try {
            List<Map<String, Object>> choices = (List<Map<String, Object>>) response.get("choices");
            if (choices != null && !choices.isEmpty()) {
                Map<String, Object> firstChoice = choices.get(0);
                Map<String, Object> message = (Map<String, Object>) firstChoice.get("message");
                return (String) message.get("content");
            }
        } catch (Exception e) {
            log.warn("Failed to extract content from OpenRouter response", e);
        }
        return "{}";
    }

    private List<ScanResult> parseVulnerabilitiesFromResponse(String content, Plugin plugin) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            log.debug("Attempting to parse OpenRouter response as JSON");
            log.debug("Response content: {}", content);
            
            // Try to extract JSON from the response if it contains text before/after
            String jsonContent = extractJsonFromResponse(content);
            
            // Try to parse as JSON
            JsonNode root = objectMapper.readTree(jsonContent);
            log.debug("Parsed JSON root type: {}", root.getNodeType());
            
            if (root.isArray()) {
                log.info("Found array of vulnerabilities: {} items", root.size());
                for (JsonNode vuln : root) {
                    ScanResult result = createScanResultFromJson(vuln, plugin);
                    if (result != null) {
                        results.add(result);
                    }
                }
            } else if (root.has("vulnerabilities") && root.get("vulnerabilities").isArray()) {
                log.info("Found vulnerabilities array: {} items", root.get("vulnerabilities").size());
                for (JsonNode vuln : root.get("vulnerabilities")) {
                    ScanResult result = createScanResultFromJson(vuln, plugin);
                    if (result != null) {
                        results.add(result);
                    }
                }
            } else {
                log.warn("No vulnerabilities array found in JSON response. Root keys: {}", root.fieldNames());
            }
        } catch (Exception e) {
            log.warn("Failed to parse OpenRouter response as JSON: {}", e.getMessage());
            log.debug("Response content that failed to parse: {}", content);
            
            // Try to create a basic vulnerability from the text response
            if (content.toLowerCase().contains("vulnerability") || content.toLowerCase().contains("security")) {
                log.info("Attempting to create basic vulnerability from text response");
                return createBasicVulnerabilityFromText(content, plugin);
            }
            
            return new ArrayList<>();
        }
        
        // If no vulnerabilities found, return empty list
        if (results.isEmpty()) {
            log.info("No vulnerabilities found in OpenRouter response");
        }
        
        return results;
    }
    
    private String extractJsonFromResponse(String content) {
        // Look for JSON array or object in the response
        int jsonStart = -1;
        int jsonEnd = -1;
        
        // Find the start of JSON (look for [ or {)
        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '[' || c == '{') {
                jsonStart = i;
                break;
            }
        }
        
        if (jsonStart == -1) {
            log.warn("No JSON found in response, returning original content");
            return content;
        }
        
        // Find the matching closing bracket/brace
        int braceCount = 0;
        boolean inString = false;
        char startChar = content.charAt(jsonStart);
        char endChar = (startChar == '[') ? ']' : '}';
        
        for (int i = jsonStart; i < content.length(); i++) {
            char c = content.charAt(i);
            
            if (c == '"' && (i == 0 || content.charAt(i-1) != '\\')) {
                inString = !inString;
            }
            
            if (!inString) {
                if (c == startChar) {
                    braceCount++;
                } else if (c == endChar) {
                    braceCount--;
                    if (braceCount == 0) {
                        jsonEnd = i + 1;
                        break;
                    }
                }
            }
        }
        
        if (jsonEnd == -1) {
            log.warn("Could not find matching closing bracket, returning original content");
            return content;
        }
        
        String jsonContent = content.substring(jsonStart, jsonEnd);
        log.debug("Extracted JSON content: {}", jsonContent);
        return jsonContent;
    }
    
    private List<ScanResult> createBasicVulnerabilityFromText(String content, Plugin plugin) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            // Create a basic vulnerability from the text response
            ScanResult basicVuln = ScanResult.builder()
                    .plugin(plugin)
                    .severity("INFO")
                    .vulnerabilityId("AI Analysis Result")
                    .vulnerabilityName("Security Analysis Report")
                    .cvssScore(0.0)
                    .description("AI analysis completed. Please review the full response for detailed findings.")
                    .fixSuggestion("Review the analysis and implement recommended security improvements.")
                    .aiSuggestion("AI Response:\n" + content)
                    .build();
            
            results.add(basicVuln);
            log.info("Created basic vulnerability from text response");
            
        } catch (Exception e) {
            log.warn("Failed to create basic vulnerability from text", e);
        }
        
        return results;
    }

    private ScanResult createScanResultFromJson(JsonNode vuln, Plugin plugin) {
        try {
            String name = vuln.has("name") ? vuln.get("name").asText() : "Unknown Vulnerability";
            String severity = vuln.has("severity") ? vuln.get("severity").asText() : "MEDIUM";
            String description = vuln.has("description") ? vuln.get("description").asText() : "No description available";
            Double cvssScore = vuln.has("cvss_score") ? vuln.get("cvss_score").asDouble() : 5.0;
            String fixSuggestion = vuln.has("fix_suggestion") ? vuln.get("fix_suggestion").asText() : "No fix suggestion available";
            
            // Build detailed AI suggestion with file path, line number, and code changes
            StringBuilder aiSuggestionBuilder = new StringBuilder();
            
            if (vuln.has("file_path") && vuln.has("line_number")) {
                String filePath = vuln.get("file_path").asText();
                String lineNumber = vuln.get("line_number").asText();
                aiSuggestionBuilder.append("📍 File: ").append(filePath).append(" (Line ").append(lineNumber).append(")\n\n");
            }
            
            if (vuln.has("vulnerable_code")) {
                aiSuggestionBuilder.append("🔴 Current Vulnerable Code:\n");
                aiSuggestionBuilder.append("```\n").append(vuln.get("vulnerable_code").asText()).append("\n```\n\n");
            }
            
            if (vuln.has("fixed_code")) {
                aiSuggestionBuilder.append("🟢 Fixed Code:\n");
                aiSuggestionBuilder.append("```\n").append(vuln.get("fixed_code").asText()).append("\n```\n\n");
            }
            
            if (vuln.has("ai_suggestion")) {
                aiSuggestionBuilder.append("💡 Detailed Explanation:\n");
                aiSuggestionBuilder.append(vuln.get("ai_suggestion").asText());
            } else {
                aiSuggestionBuilder.append("💡 No detailed explanation provided by AI.");
            }
            
            String aiSuggestion = aiSuggestionBuilder.toString();
            
            return ScanResult.builder()
                    .plugin(plugin)
                    .severity(severity)
                    .vulnerabilityId(name)
                    .vulnerabilityName(name)
                    .cvssScore(cvssScore)
                    .description(description)
                    .fixSuggestion(fixSuggestion)
                    .aiSuggestion(aiSuggestion)
                    .build();
        } catch (Exception e) {
            log.warn("Failed to create ScanResult from JSON", e);
            return null;
        }
    }


}
