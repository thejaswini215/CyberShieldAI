package com.cybershield.dto;

import jakarta.validation.constraints.NotBlank;

public class ScanRequestDto {

    @NotBlank(message = "URL must not be blank")
    private String url;

    public ScanRequestDto() {}

    public ScanRequestDto(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
