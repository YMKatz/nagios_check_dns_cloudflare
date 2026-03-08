package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/ips"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/cloudflare/cloudflare-go/v6/zones"
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
		return nil, fmt.Errorf("Unable to create cache: %w", err)
	}

	writeable, err := Writeable(abs)
	if err != nil {
		return nil, fmt.Errorf("Unable to create cache: %w", err)
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

func (c *CFCache) LoadCloudflareIPList(ctx context.Context, client *cloudflare.Client) error {
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

	cfResp, err := client.IPs.List(ctx, ips.IPListParams{})
	if err != nil {
		return fmt.Errorf("Unable to query Cloudflare for public IPs: %w", err)
	}
	c.PublicCIDRsV4, err = parseIPNetList(cfResp.IPV4CIDRs.([]string))
	if err != nil {
		return fmt.Errorf("Unable to parse Cloudflare IPv4 CIDRs: %w", err)
	}
	c.PublicCIDRsV6, err = parseIPNetList(cfResp.IPV6CIDRs.([]string))
	if err != nil {
		return fmt.Errorf("Unable to parse Cloudflare IPv6 CIDRs: %w", err)
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
			errs = multierror.Append(errs, fmt.Errorf("Unable to parse CIDR: %w", err))
		}
	}

	return ips, errs.ErrorOrNil()
}

func (c *CFCache) GetCFZoneDNS(ctx context.Context, cfAPI *cloudflare.Client, domain string) ([]dns.RecordResponse, error) {
	domainKey := strings.ReplaceAll(domain, ".", "_")
	exp, _ := c.cache.Read(keyPrefixCloudflareZoneStaleAfter + domainKey)
	var expires time.Time
	err := expires.UnmarshalBinary(exp)

	var records []dns.RecordResponse

	// If we had an unmarshalling error, just assume we don't have cached data
	// If it is expired, clear it
	// If any error happens here, just clear the cache and query again
	if err == nil && expires.After(time.Now()) {
		dnsList, err := c.cache.ReadStream(keyPrefixCloudflareDNS+domainKey, false)
		if err == nil {
			err = json.NewDecoder(dnsList).Decode(&records)
			if err == nil {
				fmt.Fprintf(os.Stderr, "Loaded CF Zone from cache for %s\n", domain)
				return records, nil
			}
		}
	}

	_ = c.cache.Erase(keyPrefixCloudflareZoneStaleAfter + domainKey)
	_ = c.cache.Erase(keyPrefixCloudflareZone + domainKey)
	_ = c.cache.Erase(keyPrefixCloudflareDNS + domainKey)

	fmt.Fprintf(os.Stderr, "Getting CF Zone ID from domain %s\n", domain)
	zones, err := cfAPI.Zones.List(
		ctx,
		zones.ZoneListParams{
			Name: cloudflare.F(domain),
		},
		option.WithRequestTimeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("Unable to query Cloudflare Zone ID for domain: %w", err)
	}
	if len(zones.Result) != 1 {
		return nil, fmt.Errorf("Unable to find Cloudflare Zone ID for domain - result length: %d", len(zones.Result))
	}
	zoneId := zones.Result[0].ID
	fmt.Fprintf(os.Stderr, "Got CF ZoneID %s for %s\n", zoneId, domain)

	_ = c.cache.WriteString(keyPrefixCloudflareZone+domainKey, zoneId)

	recordPager := cfAPI.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflare.String(zoneId),
	})
	for recordPager.Next() {
		fmt.Fprintf(os.Stderr, "Getting CF DNS record %d\n", recordPager.Index())
		records = append(records, recordPager.Current())
	}
	if err := recordPager.Err(); err != nil {
		return nil, fmt.Errorf("Unable to query Cloudflare for DNS records: %w", err)
	}

	encodedRecords, _ := json.Marshal(records)

	_ = c.cache.Write(keyPrefixCloudflareDNS+domainKey, encodedRecords)
	expiresB, _ := time.Now().Add(time.Minute * time.Duration(5)).MarshalBinary()
	_ = c.cache.Write(keyPrefixCloudflareZoneStaleAfter+domainKey, expiresB)

	return records, nil
}
