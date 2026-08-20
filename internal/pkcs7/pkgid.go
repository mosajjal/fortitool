package pkcs7

import "regexp"

// pkgIDPattern mirrors scripts/pkgtool.py's pkg_ids() regex exactly:
//
//	rb"[0-9A-Z]{8}(" + b"|".join(codes) + rb")\d{5}-\d{9}-\d{10}"
var pkgIDPattern = regexp.MustCompile(
	`[0-9A-Z]{8}(APPDB|AVDB|AVEN|DBDB|FLDB|FLEN|ISDB|MMDB|MUDB|NIDS)\d{5}-\d{9}-\d{10}`,
)

// FindPackageIDs finds FortiGuard package identifiers embedded in payload,
// e.g. "06004000NIDS00105-000070059-2601051815", returning up to limit
// unique matches in order of first appearance.
func FindPackageIDs(payload []byte, limit int) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range pkgIDPattern.FindAll(payload, -1) {
		s := string(m)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	return out
}
