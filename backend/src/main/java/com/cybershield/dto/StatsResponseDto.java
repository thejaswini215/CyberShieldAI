package com.cybershield.dto;

public class StatsResponseDto {
    private long totalScans;
    private long phishingDetected;
    private long legitimateScans;
    private long highRiskThreats;

    public StatsResponseDto() {}

    public StatsResponseDto(long totalScans, long phishingDetected, long legitimateScans, long highRiskThreats) {
        this.totalScans = totalScans;
        this.phishingDetected = phishingDetected;
        this.legitimateScans = legitimateScans;
        this.highRiskThreats = highRiskThreats;
    }

    public long getTotalScans() {
        return totalScans;
    }

    public void setTotalScans(long totalScans) {
        this.totalScans = totalScans;
    }

    public long getPhishingDetected() {
        return phishingDetected;
    }

    public void setPhishingDetected(long phishingDetected) {
        this.phishingDetected = phishingDetected;
    }

    public long getLegitimateScans() {
        return legitimateScans;
    }

    public void setLegitimateScans(long legitimateScans) {
        this.legitimateScans = legitimateScans;
    }

    public long getHighRiskThreats() {
        return highRiskThreats;
    }

    public void setHighRiskThreats(long highRiskThreats) {
        this.highRiskThreats = highRiskThreats;
    }
}
