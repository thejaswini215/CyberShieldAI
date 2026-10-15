package com.cybershield.repository;

import com.cybershield.model.ScanRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<ScanRecord, Long> {
    
    List<ScanRecord> findTop50ByOrderByScannedAtDesc();

    long countByIsPhishing(boolean isPhishing);

    @Query("SELECT COUNT(s) FROM ScanRecord s WHERE s.riskLevel = 'High'")
    long countHighRisk();
}
