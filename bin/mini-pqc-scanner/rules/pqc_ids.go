package rules

// PQCAlgorithm represents a PQC algorithm
type PQCAlgorithm struct {
	Name        string
	Description string
	Type        string // KEM, Signature, etc.
}

// GetPQCHybridIdentifiers returns a list of known PQC/hybrid algorithm identifiers
func GetPQCHybridIdentifiers() []PQCAlgorithm {
	return []PQCAlgorithm{
		{
			Name:        "Kyber",
			Description: "Key encapsulation mechanism (KEM)",
			Type:        "KEM",
		},
		{
			Name:        "Dilithium",
			Description: "Digital signature algorithm",
			Type:        "Signature",
		},
		{
			Name:        "Falcon",
			Description: "Digital signature algorithm",
			Type:        "Signature",
		},
		{
			Name:        "SPHINCS+",
			Description: "Digital signature algorithm",
			Type:        "Signature",
		},
		{
			Name:        "NTRU",
			Description: "Key encapsulation mechanism (KEM)",
			Type:        "KEM",
		},
	}
}
