package validation

import (
	"strconv"
	"strings"
	"unicode"
)

// CompareVersions compares two software version strings (supporting Debian/RPM/Semver style).
// Returns:
//   -1 if v1 < v2
//    0 if v1 == v2
//    1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	v1 = strings.TrimSpace(v1)
	v2 = strings.TrimSpace(v2)

	if v1 == v2 {
		return 0
	}

	// Strip epoch if present (e.g. "1:1.1.1f-1" -> epoch 1)
	epoch1, v1NoEpoch := splitEpoch(v1)
	epoch2, v2NoEpoch := splitEpoch(v2)

	if epoch1 != epoch2 {
		if epoch1 < epoch2 {
			return -1
		}
		return 1
	}

	tokens1 := tokenize(v1NoEpoch)
	tokens2 := tokenize(v2NoEpoch)

	maxLen := len(tokens1)
	if len(tokens2) > maxLen {
		maxLen = len(tokens2)
	}

	for i := 0; i < maxLen; i++ {
		var t1, t2 string
		if i < len(tokens1) {
			t1 = tokens1[i]
		}
		if i < len(tokens2) {
			t2 = tokens2[i]
		}

		if t1 == t2 {
			continue
		}

		// Handle tilde ~ (Debian convention: ~ sorts before anything, even empty string)
		if t1 == "~" {
			return -1
		}
		if t2 == "~" {
			return 1
		}

		// Check if both are numeric
		num1, err1 := strconv.ParseInt(t1, 10, 64)
		num2, err2 := strconv.ParseInt(t2, 10, 64)

		if err1 == nil && err2 == nil {
			if num1 < num2 {
				return -1
			}
			if num1 > num2 {
				return 1
			}
			continue
		}

		// Lexical comparison for strings
		if t1 < t2 {
			return -1
		}
		return 1
	}

	return 0
}

func splitEpoch(v string) (int64, string) {
	idx := strings.Index(v, ":")
	if idx != -1 {
		epochStr := v[:idx]
		epoch, err := strconv.ParseInt(epochStr, 10, 64)
		if err == nil {
			return epoch, v[idx+1:]
		}
	}
	return 0, v
}

func tokenize(v string) []string {
	var tokens []string
	var current strings.Builder
	var lastType rune // 'd' digit, 'a' alpha, 'p' punctuation, 't' tilde

	for _, r := range v {
		var curType rune
		if r == '~' {
			curType = 't'
		} else if unicode.IsDigit(r) {
			curType = 'd'
		} else if unicode.IsLetter(r) {
			curType = 'a'
		} else {
			curType = 'p'
		}

		if curType == 'p' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			lastType = 'p'
			continue
		}

		if curType == 't' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, "~")
			lastType = 't'
			continue
		}

		if current.Len() > 0 && curType != lastType {
			tokens = append(tokens, current.String())
			current.Reset()
		}

		current.WriteRune(r)
		lastType = curType
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}
