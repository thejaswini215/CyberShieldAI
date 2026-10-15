package com.cybershield.controller;

import com.cybershield.dto.ScanRequestDto;
import com.cybershield.dto.ScanResponseDto;
import com.cybershield.dto.StatsResponseDto;
import com.cybershield.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public ResponseEntity<ScanResponseDto> scanUrl(@Valid @RequestBody ScanRequestDto request) {
        ScanResponseDto response = scanService.scanUrl(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    public ResponseEntity<List<ScanResponseDto>> getScanHistory() {
        return ResponseEntity.ok(scanService.getRecentScans());
    }

    @GetMapping("/stats")
    public ResponseEntity<StatsResponseDto> getStats() {
        return ResponseEntity.ok(scanService.getStats());
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "CyberShield-Backend");
        return ResponseEntity.ok(status);
    }
}
