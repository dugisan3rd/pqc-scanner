package rules

// PQCNamedGroups maps TLS group IDs to their PQC/hybrid key exchange names
// These are experimental groups used in Cloudflare and other PQC test deployments
var PQCNamedGroups = map[uint16]string{
	0xfe30: "X25519Kyber768Draft00 (Hybrid: X25519 + Kyber768)",
	0xfe31: "P256Kyber768Draft00 (Hybrid: P-256 + Kyber768)",
	0xfe32: "X25519Kyber512Draft00 (Hybrid: X25519 + Kyber512)",
	0xfe33: "Kyber768Draft00 (Standalone)",
	0xfe34: "ffdhe2048Kyber768Draft00 (Hybrid: ffdhe2048 + Kyber768)",
	0xfe35: "ffdhe3072Kyber768Draft00 (Hybrid: ffdhe3072 + Kyber768)",
	0xfe36: "ffdhe4096Kyber768Draft00 (Hybrid: ffdhe4096 + Kyber768)",
	0xfe37: "secp384r1Kyber768Draft00 (Hybrid: P-384 + Kyber768)",
	0xfe38: "x448Kyber768Draft00 (Hybrid: X448 + Kyber768)",
	// Modern hybrid ML-KEM groups (OpenSSL 3.2+/oqs-provider)
	0x11ec: "X25519MLKEM768 (Hybrid: X25519 + ML-KEM-768)",
	0x11eb: "SecP256r1MLKEM768 (Hybrid: secp256r1 + ML-KEM-768)",
	0x11ed: "SecP384r1MLKEM1024 (Hybrid: secp384r1 + ML-KEM-1024)",
}

// IsPQCGroup checks if a TLS group ID is a known PQC or hybrid key exchange group
func IsPQCGroup(groupID uint16) bool {
	_, exists := PQCNamedGroups[groupID]
	return exists
}

// IsHybridGroup checks if a TLS group ID is a hybrid key exchange group
func IsHybridGroup(groupID uint16) bool {
	_, exists := PQCNamedGroups[groupID]
	return exists && groupID != 0xfe33 // All except Kyber768Draft00 are hybrid
}
