package scan

import (
	"fmt"
	"sort"
	"strings"
)

// RecommendationKind represents whether an item is a status or a recommendation
type RecommendationKind int

const (
	// KindRecommendation indicates an item is a recommendation
	KindRecommendation RecommendationKind = iota
	// KindStatus indicates an item is a status
	KindStatus
)

// RecommendationType represents the type of recommendation
type RecommendationType int

const (
	// InfoRecommendation is an informational recommendation
	InfoRecommendation RecommendationType = iota
	// WarningRecommendation is a warning recommendation
	WarningRecommendation
	// CriticalRecommendation is a critical recommendation
	CriticalRecommendation
	// SuccessRecommendation indicates a check passed successfully
	SuccessRecommendation
)

// Evidence represents what we observed and how we observed it
type Evidence struct {
	Probe   string `json:"probe"`   // e.g. "uname -r", "apt-cache policy linux-image-generic"
	Snippet string `json:"snippet"` // short excerpt (first lines, trimmed)
}

// Recommendation represents a numbered recommendation or status item
type Recommendation struct {
	ModuleID     int                // Major number for the module (1=env, 2=firmware, etc.)
	SectionID    int                // Section within the module
	ItemID       int                // Item within the section
	Text         string             // Text of the recommendation or status
	Type         RecommendationType // Type of recommendation
	Details      string             // Additional details (if any)
	Kind         RecommendationKind // Kind of item (recommendation or status)
	Severity     int                `json:"Severity"`               // Severity score (1-5, where 1 is lowest and 5 is highest)
	FixScript    string             `json:"FixScript,omitempty"`    // Script to fix the issue (TBD automation)
	DockerInsert string             `json:"DockerInsert,omitempty"` // Docker-related automation info
	Evidence     []Evidence         `json:"Evidence,omitempty"`     // What we observed
	Confidence   string             `json:"Confidence,omitempty"`   // "high|medium|low"
	References   []string           `json:"References,omitempty"`   // URLs or docs cited
}

// CommandModules maps command names to module IDs
var CommandModules = map[string]int{
	"env":           1,
	"firmware":      2,
	"kernel":        3,
	"testca":        11,
	"testipsec":     4,
	"nginx":         5,
	"testopenssh":   6,
	"testopenvpn":   7,
	"testpostfix":   8,
	"testpgp":       9,
	"testruntime":   10,
	"parsecrt":      12,
	"testtls":       13,
	"testlib":       14,
	"testapache":    15,
	"testwireguard": 16,
	"testtcpdump":   17,
	"docker":        18,
	"apps":          20,
}

// RecommendationManager handles collecting and formatting recommendations
type RecommendationManager struct {
	Recommendations []Recommendation
}

// AppendRecommendations adds new recommendations to the manager while avoiding duplicates
func (rm *RecommendationManager) AppendRecommendations(newRecs []Recommendation) {
	// Create a map to track existing recommendations by their unique ID
	existingRecs := make(map[string]bool)

	// Add existing recommendations to the map
	for _, rec := range rm.Recommendations {
		// Include Kind in the key to differentiate between status items and recommendations
		key := fmt.Sprintf("%d.%d.%d.%d", rec.ModuleID, rec.SectionID, rec.ItemID, rec.Kind)
		existingRecs[key] = true
	}

	// Add only new recommendations that don't already exist
	for _, rec := range newRecs {
		// Include Kind in the key to differentiate between status items and recommendations
		key := fmt.Sprintf("%d.%d.%d.%d", rec.ModuleID, rec.SectionID, rec.ItemID, rec.Kind)
		if !existingRecs[key] {
			rm.Recommendations = append(rm.Recommendations, rec)
			existingRecs[key] = true
		}
	}

	// Sort recommendations by ID
	rm.SortRecommendations()
}

// SortRecommendations sorts the recommendations by ModuleID, SectionID, and ItemID
func (rm *RecommendationManager) SortRecommendations() {
	sort.Slice(rm.Recommendations, func(i, j int) bool {
		a := rm.Recommendations[i]
		b := rm.Recommendations[j]

		// Compare ModuleID first
		if a.ModuleID != b.ModuleID {
			return a.ModuleID < b.ModuleID
		}

		// If ModuleID is the same, compare SectionID
		if a.SectionID != b.SectionID {
			return a.SectionID < b.SectionID
		}

		// If both ModuleID and SectionID are the same, compare ItemID
		return a.ItemID < b.ItemID
	})
}

// NewRecommendationManager creates a new recommendation manager
func NewRecommendationManager() *RecommendationManager {
	return &RecommendationManager{
		Recommendations: make([]Recommendation, 0),
	}
}

// AddStatus adds a status item to the list
func (rm *RecommendationManager) AddStatus(moduleID, sectionID, itemID int, text string, statusType RecommendationType, details string, severity int) {
	status := Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      text,
		Type:      statusType,
		Details:   details,
		Kind:      KindStatus, // Set as status kind
		Severity:  severity,   // Set severity score
	}
	rm.Recommendations = append(rm.Recommendations, status)
}

// GetRecommendations returns all recommendations and status items
func (rm *RecommendationManager) GetRecommendations() []Recommendation {
	// Make sure recommendations are sorted before returning
	rm.SortRecommendations()
	return rm.Recommendations
}

// FormatRecommendations formats all recommendations and status items as a string
func (rm *RecommendationManager) FormatRecommendations() string {
	// Split recommendations and status items
	var statusItems []Recommendation
	var recommendationItems []Recommendation

	for _, item := range rm.Recommendations {
		if item.Kind == KindStatus {
			statusItems = append(statusItems, item)
		} else {
			recommendationItems = append(recommendationItems, item)
		}
	}

	var b strings.Builder

	// Format status items if any
	if len(statusItems) > 0 {
		b.WriteString("\nStatus:\n------------------\n")
		currentModule := -1
		firstModule := true

		for _, rec := range statusItems {
			// New module
			if rec.ModuleID != currentModule {
				currentModule = rec.ModuleID
				modulePrefix := ""
				for cmd, id := range CommandModules {
					if id == currentModule {
						modulePrefix = cmd
						break
					}
				}
				// Add extra line space before each module header (except the first one)
				if !firstModule {
					b.WriteString("\n")
				}
				firstModule = false
				b.WriteString(fmt.Sprintf("\n%d. %s\n", currentModule, strings.ToUpper(modulePrefix)))
			}

			// Add the status item with S prefix
			statusID := fmt.Sprintf("S%d.%d.%d", rec.ModuleID, rec.SectionID, rec.ItemID)
			b.WriteString(fmt.Sprintf("\n%s %s", statusID, rec.Text))

			// Add details if any
			if rec.Details != "" {
				b.WriteString(fmt.Sprintf("\n  - %s", rec.Details))
			}
		}
		b.WriteString("\n\n")
	}

	// Format recommendation items if any
	if len(recommendationItems) > 0 {
		b.WriteString("\nRecommendations:\n------------------\n")
		currentModule := -1
		firstModule := true

		for _, rec := range recommendationItems {
			// New module
			if rec.ModuleID != currentModule {
				currentModule = rec.ModuleID
				modulePrefix := ""
				for cmd, id := range CommandModules {
					if id == currentModule {
						modulePrefix = cmd
						break
					}
				}
				// Add extra line space before each module header (except the first one)
				if !firstModule {
					b.WriteString("\n")
				}
				firstModule = false
				b.WriteString(fmt.Sprintf("\n%d. %s\n", currentModule, strings.ToUpper(modulePrefix)))
			}

			// Add the recommendation item with severity score
			recID := fmt.Sprintf("%d.%d.%d", rec.ModuleID, rec.SectionID, rec.ItemID)
			severityStr := ""
			if rec.Severity > 0 {
				severityStr = fmt.Sprintf(" [Severity: %d]", rec.Severity)
			}
			b.WriteString(fmt.Sprintf("\n%s%s %s", recID, severityStr, rec.Text))

			// Add details if any
			if rec.Details != "" {
				b.WriteString(fmt.Sprintf("\n  - %s", rec.Details))
			}
			
			// Add evidence if any (new evidence-backed architecture)
			if len(rec.Evidence) > 0 {
				b.WriteString("\n\n  Evidence:")
				for _, evidence := range rec.Evidence {
					b.WriteString(fmt.Sprintf("\n  • Probe: %s → %s", evidence.Probe, evidence.Snippet))
				}
			}
			
			// Add confidence if present
			if rec.Confidence != "" {
				b.WriteString(fmt.Sprintf("\n\n  Confidence: %s", rec.Confidence))
			}
			
			// Add references if any
			if len(rec.References) > 0 {
				b.WriteString("\n\n  References:")
				for _, ref := range rec.References {
					b.WriteString(fmt.Sprintf("\n  • %s", ref))
				}
			}
		}
	}

	// If no recommendations or status items were found
	if len(statusItems) == 0 && len(recommendationItems) == 0 {
		return "No recommendations or status items found."
	}

	return b.String()
}
