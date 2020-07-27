package dns

import (
	"golang.org/x/net/publicsuffix"
)

func GetDomainFromHostname(host string) string {
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// If we have an error, just return the original input
		return host
	}
	return etld1
}
