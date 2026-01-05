package linux

import (
    "fmt"
    "mini-pqc/scan"
)

// generateParseCrtStatus converts overall certificate statistics into status items
// with severity levels based on PQC risk assessment and certificate usage context.
// ModuleID 12 is reserved for the parsecrt command (matching its recommendation IDs).
func generateParseCrtStatus(stats map[string]int, rm *scan.RecommendationManager) {
    moduleID := scan.CommandModules["parsecrt"] // Should be 12

    // Section 1: Inventory & Priority (S12.1.x)
    
    // S12.1.1 Total certificates found → Always NONE (inventory only; no risk by itself)
    rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Total certificates found: %d", stats["total"]), scan.InfoRecommendation, "", 0)
    
    // S12.1.2 High-priority (in use) → 0 = NONE, >0 = HIGH if RSA/ECDSA, CRITICAL if expired/weak
    highPriority := stats["used"]
    if highPriority == 0 {
        rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("High-priority (in use): %d", highPriority), scan.InfoRecommendation, "", 0)
    } else {
        // Assume RSA/ECDSA are PQC-vulnerable, check for weak keys or expired certs
        if stats["expired"] > 0 || stats["weak"] > 0 {
            rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("High-priority (in use): %d", highPriority), scan.CriticalRecommendation, "Contains expired or weak key certificates", 5)
        } else {
            rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("High-priority (in use): %d", highPriority), scan.WarningRecommendation, "Contains PQC-vulnerable certificates", 4)
        }
    }
    
    // S12.1.3 Medium-priority → 0 = NONE, >0 = MODERATE if PQC-vulnerable, LOW if PQC-safe
    medium := stats["medium"]
    if medium == 0 {
        rm.AddStatus(moduleID, 1, 3, fmt.Sprintf("Medium-priority: %d", medium), scan.InfoRecommendation, "", 0)
    } else {
        // Check if contains PQC-vulnerable algorithms
        if stats["rsa"] > 0 || stats["ecdsa"] > 0 {
            rm.AddStatus(moduleID, 1, 3, fmt.Sprintf("Medium-priority: %d", medium), scan.InfoRecommendation, "Contains PQC-vulnerable certificates", 3)
        } else {
            rm.AddStatus(moduleID, 1, 3, fmt.Sprintf("Medium-priority: %d", medium), scan.InfoRecommendation, "PQC-safe certificates", 1)
        }
    }
    
    // S12.1.4 Low-priority trust store → 0 = NONE, >0 = LOW unless expired/compromised
    lowPriority := stats["low"]
    if lowPriority == 0 {
        rm.AddStatus(moduleID, 1, 4, fmt.Sprintf("Low-priority (trust store): %d", lowPriority), scan.InfoRecommendation, "", 0)
    } else {
        if stats["expired"] > 0 {
            rm.AddStatus(moduleID, 1, 4, fmt.Sprintf("Low-priority (trust store): %d", lowPriority), scan.InfoRecommendation, "Contains expired certificates", 3)
        } else {
            rm.AddStatus(moduleID, 1, 4, fmt.Sprintf("Low-priority (trust store): %d", lowPriority), scan.InfoRecommendation, "", 1)
        }
    }

    // Section 2: Algorithm breakdown (S12.2.x)
    
    // S12.2.1 RSA certs → 0 = NONE, >0 = HIGH if ≥2048, CRITICAL if <2048 or public-facing
    rsaCount := stats["rsa"]
    if rsaCount == 0 {
        rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("RSA certificates: %d", rsaCount), scan.InfoRecommendation, "", 0)
    } else {
        if stats["weak"] > 0 || stats["public_facing"] > 0 {
            rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("RSA certificates: %d", rsaCount), scan.CriticalRecommendation, "Contains weak keys (<RSA-2048) or public-facing certificates", 5)
        } else {
            rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("RSA certificates: %d", rsaCount), scan.WarningRecommendation, "PQC-vulnerable algorithm", 4)
        }
    }
    
    // S12.2.2 ECDSA certs → 0 = NONE, >0 = HIGH for P-256, MODERATE for P-384
    ecdsaCount := stats["ecdsa"]
    if ecdsaCount == 0 {
        rm.AddStatus(moduleID, 2, 2, fmt.Sprintf("ECDSA certificates: %d", ecdsaCount), scan.InfoRecommendation, "", 0)
    } else {
        if stats["p256"] > 0 {
            rm.AddStatus(moduleID, 2, 2, fmt.Sprintf("ECDSA certificates: %d", ecdsaCount), scan.WarningRecommendation, "P-256 curves are PQC-vulnerable", 4)
        } else {
            rm.AddStatus(moduleID, 2, 2, fmt.Sprintf("ECDSA certificates: %d", ecdsaCount), scan.InfoRecommendation, "P-384 CNSA-aligned but still PQC-vulnerable", 3)
        }
    }
    
    // S12.2.3 Ed25519 certs → 0 = NONE, >0 = LOW for PQC risk, HIGH if expiring >2030
    ed25519Count := stats["ed25519"]
    if ed25519Count == 0 {
        rm.AddStatus(moduleID, 2, 3, fmt.Sprintf("Ed25519 certificates: %d", ed25519Count), scan.InfoRecommendation, "", 0)
    } else {
        if stats["expiring2030"] > 0 {
            rm.AddStatus(moduleID, 2, 3, fmt.Sprintf("Ed25519 certificates: %d", ed25519Count), scan.WarningRecommendation, "Strong classical but expiring far out (>2030)", 4)
        } else {
            rm.AddStatus(moduleID, 2, 3, fmt.Sprintf("Ed25519 certificates: %d", ed25519Count), scan.InfoRecommendation, "Strong classical but still PQC-vulnerable", 1)
        }
    }
    
    // S12.2.4 DSA certs → 0 = NONE, >0 = CRITICAL (obsolete)
    dsaCount := stats["dsa"]
    if dsaCount == 0 {
        rm.AddStatus(moduleID, 2, 4, fmt.Sprintf("DSA certificates: %d", dsaCount), scan.InfoRecommendation, "", 0)
    } else {
        rm.AddStatus(moduleID, 2, 4, fmt.Sprintf("DSA certificates: %d", dsaCount), scan.CriticalRecommendation, "Obsolete algorithm", 5)
    }
    
    // S12.2.5 PQC certs → 0 = MODERATE (gap), >0 = NONE for PQC risk
    pqcCount := stats["pqc"]
    if pqcCount == 0 {
        rm.AddStatus(moduleID, 2, 5, fmt.Sprintf("PQC certificates: %d", pqcCount), scan.InfoRecommendation, "Gap in PQC readiness", 3)
    } else {
        rm.AddStatus(moduleID, 2, 5, fmt.Sprintf("PQC certificates: %d", pqcCount), scan.InfoRecommendation, "Verify chain compatibility", 0)
    }

    // Section 3: Expiry (S12.3.x)
    
    // S12.3.1 Expired certs → 0 = NONE, >0 = CRITICAL (operational outage risk)
    expiredCount := stats["expired"]
    if expiredCount == 0 {
        rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Certificates expired: %d", expiredCount), scan.InfoRecommendation, "", 0)
    } else {
        rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Certificates expired: %d", expiredCount), scan.CriticalRecommendation, "Operational outage risk, potential MITM if not replaced", 5)
    }
    
    // S12.3.2 Valid beyond 2030 → 0 = NONE, >0 = MODERATE (harvest-now/decrypt-later risk)
    beyond2030Count := stats["expiring2030"]
    if beyond2030Count == 0 {
        rm.AddStatus(moduleID, 3, 2, fmt.Sprintf("Certificates valid beyond 2030: %d", beyond2030Count), scan.InfoRecommendation, "", 0)
    } else {
        rm.AddStatus(moduleID, 3, 2, fmt.Sprintf("Certificates valid beyond 2030: %d", beyond2030Count), scan.InfoRecommendation, "Long-lived certificates have high harvest-now/decrypt-later risk", 3)
    }
}
