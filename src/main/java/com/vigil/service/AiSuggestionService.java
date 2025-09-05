package com.vigil.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Service that calls an external AI endpoint to get code fix suggestions.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AiSuggestionService {

    @Value("${ai.endpoint.url:https://ai.example.com/suggest}")
    private String aiEndpointUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Returns a formatted suggestion string from the AI model for a vulnerability description.
     * @param vulnerabilityDescription description text from the scan report
     * @return formatted suggestion string
     */
    public String getSuggestion(String vulnerabilityDescription) {
        log.info("Requesting AI suggestion for vulnerability description (length: {})", 
                vulnerabilityDescription != null ? vulnerabilityDescription.length() : 0);
        log.debug("Vulnerability description: {}", vulnerabilityDescription);
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = new HashMap<>();
            body.put("prompt", vulnerabilityDescription);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
            log.debug("Calling AI endpoint: {}", aiEndpointUrl);

            Map response = restTemplate.postForObject(aiEndpointUrl, entity, Map.class);
            if (response == null) {
                log.warn("AI service returned null response");
                return "No AI suggestion available.";
            }
            
            Object suggestion = response.getOrDefault("suggestion", "No suggestion returned by AI.");
            Object explanation = response.getOrDefault("explanation", "No explanation provided.");
            
            String result = "Suggestion:\n" + suggestion + "\n\nExplanation:\n" + explanation;
            log.info("AI suggestion generated successfully (length: {})", result.length());
            return result;
        } catch (Exception ex) {
            log.error("AI service error: {}", ex.getMessage(), ex);
            return "AI service error: " + ex.getMessage();
        }
    }
}


