package worker

import (
	"strings"

	"github.com/suppline/suppline/internal/config"
	"github.com/suppline/suppline/internal/queue"
)

// convertTolerationsToRegsync converts queue.CVEToleration to config.CVEToleration
func convertTolerationsToRegsync(queueTolerations []queue.CVEToleration) []config.CVEToleration {
	tolerations := make([]config.CVEToleration, len(queueTolerations))
	for i, qt := range queueTolerations {
		tolerations[i] = config.CVEToleration{
			ID:        qt.ID,
			Statement: qt.Statement,
			ExpiresAt: qt.ExpiresAt,
		}
	}
	return tolerations
}

// extractRepository extracts the repository from an image reference
func extractRepository(imageRef string) string {
	// Format: repository@digest
	parts := strings.Split(imageRef, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return imageRef
}

// extractDigest extracts the digest from an image reference
func extractDigest(imageRef string) string {
	// Format: repository@digest
	parts := strings.Split(imageRef, "@")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}
