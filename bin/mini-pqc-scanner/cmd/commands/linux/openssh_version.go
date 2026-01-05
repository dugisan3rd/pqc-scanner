package linux

import (
    "regexp"
    "strconv"
)

// parseOpenSSHMajorMinor extracts the OpenSSH major and minor version numbers from a version string.
// It looks for patterns like "OpenSSH_10.0", "OpenSSH 9.9p1", or similar vendor-formatted strings
// and returns (major, minor, true) on success, or (0, 0, false) if not found.
func parseOpenSSHMajorMinor(version string) (int, int, bool) {
    // Match "OpenSSH" followed by any non-digits, then capture major.minor
    re := regexp.MustCompile(`OpenSSH[^\d]*?(\d+)\.(\d+)`)
    m := re.FindStringSubmatch(version)
    if len(m) < 3 {
        return 0, 0, false
    }
    maj, err1 := strconv.Atoi(m[1])
    min, err2 := strconv.Atoi(m[2])
    if err1 != nil || err2 != nil {
        return 0, 0, false
    }
    return maj, min, true
}

// isOpenSSHAtLeast returns true if the provided version string represents
// an OpenSSH version >= (major.minor). If parsing fails, it returns false.
func isOpenSSHAtLeast(version string, major, minor int) bool {
    maj, min, ok := parseOpenSSHMajorMinor(version)
    if !ok {
        return false
    }
    if maj > major {
        return true
    }
    if maj == major && min >= minor {
        return true
    }
    return false
}
