package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/olorin/nagiosplugin"
	"github.com/simonleung8/flags"
	"github.com/ymkatz/nagios_check_dns_cloudflare/internal/cache"
	"github.com/ymkatz/nagios_check_dns_cloudflare/internal/dns"
)

var f = flags.New()

func init() {
	f.NewBoolFlag("help", "h", "Print detailed help")
	f.NewStringFlag("hostname", "H", "The name to query")
	f.NewStringFlag("dns-server", "s", "The DNS server to query. Cannot be used with --only-api")
	f.NewBoolFlag("only-dns", "d", "Only do the DNS part of the check. Cannot be used with --only-api")
	f.NewBoolFlag("only-api", "o", "Only do the API part of the check. Cannot be used with --only-dns")
	f.NewStringFlag("zone", "z", "Cloudflare Zone to query. Defaults to domain name of host. Cannot be used with --only-dns")
	f.NewStringSliceFlag("expected-address", "a", "If proxied, the expected API lookup result. If not proxied, the expected DNS lookup result.")
	f.NewStringFlag("querytype", "q", "Optional DNS record query type for non-proxied lookups where TYPE =(A, AAAA, SRV, TXT, MX, ANY)\nThe default query type is 'A' (IPv4 host entry)\nProxied lookups always look up A and AAAA")
	f.NewIntFlagWithDefault("timeout", "t", "Seconds before the check times out", 10)
	f.NewStringFlag("cache-path", "", "Cache location for API results. Defaults to the first of `NAGIOS_PLUGIN_STATE_DIRECTORY` environment variable, `/usr/local/nagios/var`, or `$TEMP`, that can be found")
	// TODO: Do we need these from the original check_dns?
	// fc.NewBoolFlag("expect-authority", "A", "Optionally expect the DNS server to be authoritative for the lookup")
	// fc.NewBoolFlag("accept-cname", "n", "Optionally accept cname responses as a valid result to a query\nThe default is to ignore cname responses as part of the result")
}

func main() {
	check := nagiosplugin.NewCheck()
	defer check.Finish()

	err := f.Parse(os.Args...)
	if err != nil {
		check.Unknownf("Invalid command line arguments provided. %s", err)
	}

	onlyDNS := f.Bool("only-dns")
	onlyAPI := f.Bool("only-api")

	if onlyAPI {
		if onlyDNS || f.IsSet("dns-server") {
			check.Unknownf("Cannot use DNS options with --only-api flag")
		}
	}

	var c *cache.CFCache
	if f.IsSet("cache-path") {
		c, err = cache.GetCache(f.String("cache-path"))
		if err != nil {
			check.Unknownf("Unwriteable cache path provided")
		}
	} else {
		cachePath, found := os.LookupEnv("NAGIOS_PLUGIN_STATE_DIRECTORY")
		if found {
			// If we get an error just look for the next possible location
			c, err = cache.GetCache(cachePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error trying NAGIOS_PLUGIN_STATE_DIRECTORY: %s\n", err)
			}
		}
		if c == nil {
			c, err = cache.GetCache("/usr/local/nagios/var/")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error trying /usr/local/nagios/var/: %s\n", err)
			}
		}
		if c == nil {
			c, err = cache.GetCache(os.TempDir())
			if err != nil {
				check.Unknownf("Unable to determine a usable cache path. Please provide one. Error: %s", err)
			}
		}
	}

	if !f.IsSet("hostname") {
		check.Criticalf("Hostname argument not provided")
	}
	hostname := f.String("hostname")
	queryType := f.String("querytype")
	expectedRaw := f.StringSlice("expected-address")
	wantRecords := make(map[string]bool, len(expectedRaw))
	for _, e := range expectedRaw {
		if strings.Contains(e, ",") {
			for _, e2 := range strings.Split(e, ",") {
				wantRecords[e2] = false
			}
		} else {
			wantRecords[e] = false
		}
	}

	isProxied := false

	if !onlyDNS {
		var cfAPI *cloudflare.API
		var cfZone string

		cfToken, found := os.LookupEnv("CLOUDFLARE_API_TOKEN")
		if !found {
			check.Unknownf("You must set the CLOUDFLARE_API_TOKEN variable")
		}

		err := c.LoadCloudflareIPList()
		if err != nil {
			check.Unknownf("Unable to load list of Cloudflare public IPs")
		}

		cfAPI, err = cloudflare.NewWithAPIToken(cfToken)
		if err != nil {
			check.Criticalf("Unable to create Cloudflare API client")
		}

		if f.IsSet("zone") {
			cfZone = f.String("zone")
		} else {
			cfZone = dns.GetDomainFromHostname(hostname)
		}

		records, err := c.GetCFZoneDNS(cfAPI, cfZone)
		if err != nil {
			check.Criticalf("Unable to query Cloudflare DNS records")
		}

		var foundRecord []string
		for _, r := range records {
			// fmt.Fprintf(os.Stderr, "RECORD: %v\n", r)
			if r.Name == hostname {
				// If we are filtering by query type, skip if this is the wrong type
				// If we are not filtering by query type, the types we care about are A, AAAA, and CNAME
				if (len(queryType) > 0 && r.Type != queryType) || (r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME") {
					continue
				}

				// Set this so we know what DNS record to expect
				// NOTE: The current behavior for multiple records with the same name
				//       is that if any of them is proxied they all are. This is probably
				//       undefined behavior but we will go with it for now.
				isProxied = isProxied || r.Proxied

				if len(wantRecords) > 0 {
					if _, ok := wantRecords[r.Content]; ok {
						wantRecords[r.Content] = true
						foundRecord = append(foundRecord, r.Content)
					} else {
						check.AddResultf(nagiosplugin.CRITICAL, "Found unexpected DNS %s record: %s", r.Type, r.Content)
					}
				} else {
					// If we don't expect a specific value, then any record is fine
					foundRecord = append(foundRecord, r.Content)
				}
			}
		}

		if len(expectedRaw) > 0 {
			// If we expected specific records, check that we found them all
			foundAll := true
			for wanted, wasFound := range wantRecords {
				foundAll = foundAll && wasFound
				if !wasFound {
					check.Criticalf("CF API missing expected DNS content %s", wanted)
				}
			}
			if foundAll {
				check.AddResultf(nagiosplugin.OK, "%s", strings.Join(foundRecord, ","))
			}
		} else if len(foundRecord) > 0 {
			check.AddResultf(nagiosplugin.OK, "%s", strings.Join(foundRecord, ","))
		} else {
			check.Criticalf("CF API does not have DNS record for %s", hostname)
		}
	}

	// Now do the DNS checks
	if !onlyAPI {
		if isProxied {
			// Always do A and AAAA lookups and make sure they are inside the CF IP ranges
			// TODO: Implement
		} else {
			// Do a regular DNS check
			// TODO: Implement
		}
	}

}