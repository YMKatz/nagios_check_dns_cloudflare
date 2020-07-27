package cache

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	errors "emperror.dev/errors"
	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/go-multierror"
	"github.com/peterbourgon/diskv/v3"
)

const (
	keyCloudFlareIPRangesV4           = "cf-ip-ranges-v4"
	keyCloudFlareIPRangesV6           = "cf-ip-ranges-v6"
	keyCloudFlareIPRangesStaleAfter   = "cf-ip-ranges-stale-after"
	keyPrefixCloudflareZone           = "cf-zone-"
	keyPrefixCloudflareZoneStaleAfter = "cf-zone-stale-after-"
	keyPrefixCloudflareDNS            = "cf-zone-dns-"
)

type CFCache struct {
	PublicCIDRsV4 []*net.IPNet
	PublicCIDRsV6 []*net.IPNet
	cache         *diskv.Diskv
}

func GetCache(path string) (*CFCache, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create cache")
	}

	writeable, err := Writeable(abs)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create cache")
	}
	if !writeable {
		return nil, errors.New("Trying to create cache in an unwriteable location")
	}

	return &CFCache{
		cache: diskv.New(diskv.Options{
			BasePath:     abs + "/check_dns_cloudflare.cache",
			CacheSizeMax: 1024 * 1024, // 1MB
		}),
	}, nil
}

func (c *CFCache) LoadCloudflareIPList() error {
	exp, _ := c.cache.Read(keyCloudFlareIPRangesStaleAfter)
	var expires time.Time
	err := expires.UnmarshalBinary(exp)

	// If we had an unmarshalling error, just assume we don't have cached data
	// If it is expired, clear it
	// If any error happens here, just clear the cache and query again
	if err == nil && expires.After(time.Now()) {
		needed := 2
		ipList4, err := c.cache.ReadStream(keyCloudFlareIPRangesV4, false)
		if err == nil {
			err = json.NewDecoder(ipList4).Decode(&c.PublicCIDRsV4)
			if err == nil {
				needed = needed - 1
			}
		}
		ipList6, err := c.cache.ReadStream(keyCloudFlareIPRangesV6, false)
		if err == nil {
			err = json.NewDecoder(ipList6).Decode(&c.PublicCIDRsV6)
			if err == nil {
				needed = needed - 1
			}
		}
		if needed == 0 {
			fmt.Fprint(os.Stderr, "Loaded CF CIDRs from cache\n")
			return nil
		}
	}

	_ = c.cache.Erase(keyCloudFlareIPRangesStaleAfter)
	_ = c.cache.Erase(keyCloudFlareIPRangesV4)
	_ = c.cache.Erase(keyCloudFlareIPRangesV6)

	cfResp, err := cloudflare.IPs()
	if err != nil {
		return errors.Wrap(err, "Unable to query Cloudflare for public IPs")
	}
	c.PublicCIDRsV4, err = parseIPNetList(cfResp.IPv4CIDRs)
	if err != nil {
		return errors.Wrap(err, "Unable to parse Cloudflare IPv4 CIDRs")
	}
	c.PublicCIDRsV6, err = parseIPNetList(cfResp.IPv6CIDRs)
	if err != nil {
		return errors.Wrap(err, "Unable to parse Cloudflare IPv6 CIDRs")
	}

	encodedIPv4s, _ := json.Marshal(c.PublicCIDRsV4)
	encodedIPv6s, _ := json.Marshal(c.PublicCIDRsV6)

	_ = c.cache.Write(keyCloudFlareIPRangesV4, encodedIPv4s)
	_ = c.cache.Write(keyCloudFlareIPRangesV6, encodedIPv6s)
	expiresB, _ := time.Now().AddDate(0, 0, 30).MarshalBinary()
	_ = c.cache.Write(keyCloudFlareIPRangesStaleAfter, expiresB)

	return nil
}

func parseIPNetList(strs []string) ([]*net.IPNet, error) {
	var ips []*net.IPNet
	var errs *multierror.Error

	for _, cidr := range strs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			ips = append(ips, ipNet)
		} else {
			errs = multierror.Append(errs, errors.Wrap(err, "Unable to parse CIDR"))
		}
	}

	return ips, errs.ErrorOrNil()
}

func (c *CFCache) GetCFZoneDNS(cfAPI *cloudflare.API, domain string) ([]cloudflare.DNSRecord, error) {
	domainKey := strings.ReplaceAll(domain, ".", "_")
	exp, _ := c.cache.Read(keyPrefixCloudflareZoneStaleAfter + domainKey)
	var expires time.Time
	err := expires.UnmarshalBinary(exp)

	var records []cloudflare.DNSRecord

	// If we had an unmarshalling error, just assume we don't have cached data
	// If it is expired, clear it
	// If any error happens here, just clear the cache and query again
	if err == nil && expires.After(time.Now()) {
		dnsList, err := c.cache.ReadStream(keyPrefixCloudflareDNS+domainKey, false)
		if err == nil {
			err = json.NewDecoder(dnsList).Decode(&records)
			if err == nil {
				return records, nil
			}
		}
	}

	_ = c.cache.Erase(keyPrefixCloudflareZoneStaleAfter + domainKey)
	_ = c.cache.Erase(keyPrefixCloudflareZone + domainKey)
	_ = c.cache.Erase(keyPrefixCloudflareDNS + domainKey)

	zoneId, err := cfAPI.ZoneIDByName(domain)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to query Cloudflare Zone ID for domain")
	}

	_ = c.cache.WriteString(keyPrefixCloudflareZone+domainKey, zoneId)

	records, err = cfAPI.DNSRecords(zoneId, cloudflare.DNSRecord{})
	if err != nil {
		return nil, errors.Wrap(err, "Unable to query Cloudflare for DNS records")
	}

	encodedRecords, _ := json.Marshal(records)

	_ = c.cache.Write(keyPrefixCloudflareDNS+domainKey, encodedRecords)
	expiresB, _ := time.Now().Add(time.Minute * time.Duration(5)).MarshalBinary()
	_ = c.cache.Write(keyPrefixCloudflareZoneStaleAfter+domainKey, expiresB)

	return records, nil
}
