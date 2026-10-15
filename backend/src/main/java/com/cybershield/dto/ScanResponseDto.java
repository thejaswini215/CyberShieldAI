package com.cybershield.dto;

import java.time.LocalDateTime;
import java.util.List;

public class ScanResponseDto {
    private Long id;
    private String url;
    private String prediction;
    private boolean isPhishing;
    private Double confidence;
    private String riskLevel;
    private String summary;
    private List<String> suspiciousIndicators;
    private List<String> recommendations;
    private LocalDateTime scannedAt;

    public ScanResponseDto() {}

    public ScanResponseDto(Long id, String url, String prediction, boolean isPhishing, Double confidence, 
                           String riskLevel, String summary, List<String> suspiciousIndicators, 
                           List<String> recommendations, LocalDateTime scannedAt) {
        this.id = id;
        this.url = url;
        this.prediction = prediction;
        this.isPhishing = isPhishing;
        this.confidence = confidence;
        this.riskLevel = riskLevel;
        this.summary = summary;
        this.suspiciousIndicators = suspiciousIndicators;
        this.recommendations = recommendations;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public boolean isPhishing() {
        return isPhishing;
    }

    public void setPhishing(boolean phishing) {
        isPhishing = phishing;
    }

    public Double getConfidence() {
        return confidence;
    }

    public void setConfidence(Double confidence) {
        this.confidence = confidence;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getSuspiciousIndicators() {
        return suspiciousIndicators;
    }

    public void setSuspiciousIndicators(List<String> suspiciousIndicators) {
        this.suspiciousIndicators = suspiciousIndicators;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<String> recommendations) {
        this.recommendations = recommendations;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }
}
