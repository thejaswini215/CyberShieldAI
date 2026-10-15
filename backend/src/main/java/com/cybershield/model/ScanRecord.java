package com.cybershield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_records")
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(nullable = false)
    private String prediction;

    @Column(name = "is_phishing", nullable = false)
    private boolean isPhishing;

    @Column(nullable = false)
    private Double confidence;

    @Column(name = "risk_level", nullable = false)
    private String riskLevel;

    @Column(length = 2048)
    private String summary;

    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt;

    public ScanRecord() {
        this.scannedAt = LocalDateTime.now();
    }

    public ScanRecord(String url, String prediction, boolean isPhishing, Double confidence, String riskLevel, String summary) {
        this.url = url;
        this.prediction = prediction;
        this.isPhishing = isPhishing;
        this.confidence = confidence;
        this.riskLevel = riskLevel;
        this.summary = summary;
        this.scannedAt = LocalDateTime.now();
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

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }
}
