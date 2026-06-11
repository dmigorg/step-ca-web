package cnf

import (
	"fmt"
	"regexp"
	"strings"
)

// CNFConfig represents a parsed OpenSSL configuration file
type CNFConfig struct {
	Sections map[string]map[string]string
}

// ParsedResult represents the extracted values from a CNF file
type ParsedResult struct {
	CommonName         string   `json:"commonName"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizationalUnit,omitempty"`
	Country            string   `json:"country,omitempty"`
	State              string   `json:"state,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	DNSNames           []string `json:"dnsNames,omitempty"`
	IPAddresses        []string `json:"ipAddresses,omitempty"`
	EmailAddresses     []string `json:"emailAddresses,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	KeyUsage           []string `json:"keyUsage,omitempty"`
	ExtKeyUsage        []string `json:"extKeyUsage,omitempty"`
}

// Parse parses an OpenSSL CNF file content
func Parse(content string) (*CNFConfig, error) {
	config := &CNFConfig{
		Sections: make(map[string]map[string]string),
	}

	var currentSection string
	lines := strings.Split(content, "\n")

	sectionRegex := regexp.MustCompile(`^\s*\[\s*([^\]]+)\s*\]\s*$`)
	commentRegex := regexp.MustCompile(`^\s*#`)
	emptyRegex := regexp.MustCompile(`^\s*$`)
	kvRegex := regexp.MustCompile(`^\s*([^=]+?)\s*=\s*(.*?)\s*$`)

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		if emptyRegex.MatchString(line) || commentRegex.MatchString(line) {
			continue
		}

		if matches := sectionRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentSection = strings.TrimSpace(matches[1])
			if config.Sections[currentSection] == nil {
				config.Sections[currentSection] = make(map[string]string)
			}
			continue
		}

		if currentSection != "" {
			if matches := kvRegex.FindStringSubmatch(line); len(matches) > 2 {
				key := strings.TrimSpace(matches[1])
				value := strings.TrimSpace(matches[2])
				config.Sections[currentSection][key] = value
			}
		}
	}

	return config, nil
}

// ExtractValues extracts certificate-related values from the CNF config
func (c *CNFConfig) ExtractValues() (*ParsedResult, error) {
	result := &ParsedResult{}

	// Find the req section to get dn section name
	reqSection := c.Sections["req"]
	dnSectionName := "dn"
	if reqSection != nil {
		if dn := reqSection["distinguished_name"]; dn != "" {
			dnSectionName = dn
		}
	}

	// Parse distinguished name section
	dnSection := c.Sections[dnSectionName]
	if dnSection != nil {
		result.CommonName = dnSection["CN"]
		if result.CommonName == "" {
			result.CommonName = dnSection["commonName"]
		}
		result.Organization = dnSection["organizationName"]
		if result.Organization == "" {
			result.Organization = dnSection["O"]
		}
		result.OrganizationalUnit = dnSection["organizationalUnitName"]
		if result.OrganizationalUnit == "" {
			result.OrganizationalUnit = dnSection["OU"]
		}
		result.Country = dnSection["countryName"]
		if result.Country == "" {
			result.Country = dnSection["C"]
		}
		result.State = dnSection["stateOrProvinceName"]
		if result.State == "" {
			result.State = dnSection["ST"]
		}
		result.Locality = dnSection["localityName"]
		if result.Locality == "" {
			result.Locality = dnSection["L"]
		}
	}

	// Find req_extensions section name
	reqExtSectionName := ""
	if reqSection != nil {
		reqExtSectionName = reqSection["req_extensions"]
	}

	// Also check x509_extensions
	x509ExtSectionName := ""
	if reqSection != nil {
		x509ExtSectionName = reqSection["x509_extensions"]
	}

	// Parse extensions (try both req_extensions and x509_extensions)
	for _, extSectionName := range []string{reqExtSectionName, x509ExtSectionName} {
		if extSectionName == "" {
			continue
		}
		extSection := c.Sections[extSectionName]
		if extSection == nil {
			continue
		}

		// Parse subjectAltName
		if san := extSection["subjectAltName"]; san != "" {
			c.parseSANs(san, result)
		}

		// Parse keyUsage
		if ku := extSection["keyUsage"]; ku != "" {
			result.KeyUsage = splitAndTrim(ku, ",")
		}

		// Parse extendedKeyUsage
		if eku := extSection["extendedKeyUsage"]; eku != "" {
			result.ExtKeyUsage = splitAndTrim(eku, ",")
		}
	}

	// Also check v3_ca or v3_req sections directly
	for _, sectionName := range []string{"v3_ca", "v3_req", "v3_ext"} {
		section := c.Sections[sectionName]
		if section == nil {
			continue
		}
		if san := section["subjectAltName"]; san != "" {
			c.parseSANs(san, result)
		}
		if ku := section["keyUsage"]; ku != "" && len(result.KeyUsage) == 0 {
			result.KeyUsage = splitAndTrim(ku, ",")
		}
		if eku := section["extendedKeyUsage"]; eku != "" && len(result.ExtKeyUsage) == 0 {
			result.ExtKeyUsage = splitAndTrim(eku, ",")
		}
	}

	return result, nil
}

func (c *CNFConfig) parseSANs(san string, result *ParsedResult) {
	san = strings.TrimSpace(san)

	// Check if it's a reference to another section (@alternate_names)
	if strings.HasPrefix(san, "@") {
		sectionName := strings.TrimPrefix(san, "@")
		section := c.Sections[sectionName]
		if section != nil {
			c.parseSANSection(section, result)
		}
		return
	}

	// Inline SANs: DNS:example.com, IP:1.2.3.4
	parts := splitAndTrim(san, ",")
	for _, part := range parts {
		c.parseSingleSAN(part, result)
	}
}

func (c *CNFConfig) parseSANSection(section map[string]string, result *ParsedResult) {
	for key, value := range section {
		keyLower := strings.ToLower(key)
		value = strings.TrimSpace(value)

		if strings.HasPrefix(keyLower, "dns.") {
			result.DNSNames = append(result.DNSNames, value)
		} else if strings.HasPrefix(keyLower, "ip.") {
			result.IPAddresses = append(result.IPAddresses, value)
		} else if strings.HasPrefix(keyLower, "email.") {
			result.EmailAddresses = append(result.EmailAddresses, value)
		} else if strings.HasPrefix(keyLower, "uri.") {
			result.URIs = append(result.URIs, value)
		}
	}
}

func (c *CNFConfig) parseSingleSAN(san string, result *ParsedResult) {
	parts := strings.SplitN(san, ":", 2)
	if len(parts) != 2 {
		return
	}

	sanType := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	switch sanType {
	case "dns":
		result.DNSNames = append(result.DNSNames, value)
	case "ip":
		result.IPAddresses = append(result.IPAddresses, value)
	case "email":
		result.EmailAddresses = append(result.EmailAddresses, value)
	case "uri":
		result.URIs = append(result.URIs, value)
	}
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// GetAllSANs returns combined DNS + IP SANs as a flat list
func (r *ParsedResult) GetAllSANs() []string {
	var sans []string
	sans = append(sans, r.DNSNames...)
	sans = append(sans, r.IPAddresses...)
	sans = append(sans, r.EmailAddresses...)
	sans = append(sans, r.URIs...)
	return sans
}

// Validate checks if the parsed result has minimum required fields
func (r *ParsedResult) Validate() error {
	if r.CommonName == "" {
		return fmt.Errorf("commonName (CN) is required in the [dn] section")
	}
	return nil
}
