package com.cybershield.service;

import com.cybershield.dto.PythonAgentResponse;
import com.cybershield.dto.ScanRequestDto;
import com.cybershield.dto.ScanResponseDto;
import com.cybershield.dto.StatsResponseDto;
import com.cybershield.model.ScanRecord;
import com.cybershield.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class ScanService {

    private static final Logger logger = LoggerFactory.getLogger(ScanService.class);

    private final ScanRepository scanRepository;
    private final RestTemplate restTemplate;

    @Value("${cybershield.ai-service.url:http://localhost:8000}")
    private String aiServiceUrl;

    public ScanService(ScanRepository scanRepository, RestTemplate restTemplate) {
        this.scanRepository = scanRepository;
        this.restTemplate = restTemplate;
    }

    public ScanResponseDto scanUrl(ScanRequestDto request) {
        String targetUrl = request.getUrl().trim();
        logger.info("Scanning URL: {}", targetUrl);

        PythonAgentResponse agentResponse = callPythonAiAgent(targetUrl);

        // Persist scan history to database
        ScanRecord record = new ScanRecord(
                agentResponse.getUrl(),
                agentResponse.getPrediction(),
                agentResponse.isPhishing(),
                agentResponse.getConfidence(),
                agentResponse.getRiskLevel(),
                agentResponse.getSummary()
        );
        ScanRecord saved = scanRepository.save(record);

        return new ScanResponseDto(
                saved.getId(),
                saved.getUrl(),
                saved.getPrediction(),
                saved.isPhishing(),
                saved.getConfidence(),
                saved.getRiskLevel(),
                saved.getSummary(),
                agentResponse.getSuspiciousIndicators() != null ? agentResponse.getSuspiciousIndicators() : Collections.emptyList(),
                agentResponse.getRecommendations() != null ? agentResponse.getRecommendations() : Collections.emptyList(),
                saved.getScannedAt()
        );
    }

    public List<ScanResponseDto> getRecentScans() {
        return scanRepository.findTop50ByOrderByScannedAtDesc().stream()
                .map(record -> new ScanResponseDto(
                        record.getId(),
                        record.getUrl(),
                        record.getPrediction(),
                        record.isPhishing(),
                        record.getConfidence(),
                        record.getRiskLevel(),
                        record.getSummary(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        record.getScannedAt()
                ))
                .collect(Collectors.toList());
    }

    public StatsResponseDto getStats() {
        long total = scanRepository.count();
        long phishing = scanRepository.countByIsPhishing(true);
        long legitimate = scanRepository.countByIsPhishing(false);
        long highRisk = scanRepository.countHighRisk();

        return new StatsResponseDto(total, phishing, legitimate, highRisk);
    }

    private PythonAgentResponse callPythonAiAgent(String url) {
        String endpoint = aiServiceUrl + "/agent/analyze";
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            Map<String, String> body = Collections.singletonMap("url", url);
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<PythonAgentResponse> response = restTemplate.postForEntity(
                    endpoint,
                    entity,
                    PythonAgentResponse.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
        } catch (Exception ex) {
            logger.warn("Could not reach Python AI agent at {}: {}. Utilizing fallback heuristics.", endpoint, ex.getMessage());
        }

        // Fallback analysis if Python microservice is not online
        return createFallbackAnalysis(url);
    }

    private PythonAgentResponse createFallbackAnalysis(String url) {
        PythonAgentResponse fallback = new PythonAgentResponse();
        fallback.setUrl(url);
        boolean suspicious = url.contains("@") || url.length() > 80 || url.contains("//") || url.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
        
        fallback.setPhishing(suspicious);
        fallback.setPrediction(suspicious ? "Potential Phishing" : "Likely Legitimate");
        fallback.setConfidence(0.70);
        fallback.setRiskLevel(suspicious ? "Medium" : "Low");
        fallback.setSummary("Preliminary heuristic scan completed (Python AI service offline fallback).");

        List<String> indicators = new ArrayList<>();
        if (suspicious) {
            indicators.add("Structural heuristics flagged abnormal pattern in URL structure.");
        }
        fallback.setSuspiciousIndicators(indicators);

        List<String> recommendations = new ArrayList<>();
        recommendations.add("Verify sender identity before entering credentials.");
        recommendations.add("Check domain authenticity in browser URL bar.");
        fallback.setRecommendations(recommendations);

        return fallback;
    }
}
