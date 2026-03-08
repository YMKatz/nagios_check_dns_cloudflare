package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/olorin/nagiosplugin"
	"github.com/pkg/profile"
	"github.com/simonleung8/flags"
	"github.com/ymkatz/nagios_check_dns_cloudflare/internal/cache"
	"github.com/ymkatz/nagios_check_dns_cloudflare/internal/dns"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var f = flags.New()

func init() {
	f.NewBoolFlag("help", "h", "Print detailed help")
	f.NewBoolFlag("debug", "", "Print verbose debug output")
	f.NewBoolFlag("version", "V", "Print the version information")
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
	f.NewBoolFlag("memprofile", "", "")
	f.NewBoolFlag("memprofileall", "", "")
}

func main() {
	err := f.Parse(os.Args...)

	ctx := context.Background()
	if f.IsSet("timeout") {
		newCtx, cancel := context.WithTimeout(ctx, time.Duration(f.Int("timeout"))*time.Second)
		ctx = newCtx
		defer cancel()
	}

	var memP interface{ Stop() }
	if f.IsSet("memprofile") {
		cwd, _ := os.Getwd()
		memP = profile.Start(profile.MemProfile, profile.ProfilePath(cwd))
	}
	if f.IsSet("memprofileall") {
		cwd, _ := os.Getwd()
		memP = profile.Start(profile.MemProfile, profile.ProfilePath(cwd), profile.MemProfileRate(1))
	}

	check := nagiosplugin.NewCheck()
	defer check.Finish()

	if err != nil {
		check.Unknownf("Invalid command line arguments provided: %s", err)
	}

	if f.IsSet("help") {
		fmt.Println(f.ShowUsage(4))
		os.Exit(0)
	}

	if f.IsSet("version") {
		fmt.Printf("check_dns_cloudflare %s, commit %s, built at %s by %s\n", version, commit, date, builtBy)
		os.Exit(0)
	}

	verbose := f.IsSet("debug")

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
			check.Unknownf("Unwriteable cache path provided: %s", err.Error())
		} else if verbose {
			fmt.Fprintf(os.Stderr, "Using cache from path '%s'\n", f.String("cache-path"))
		}
	} else {
		cachePath, found := os.LookupEnv("NAGIOS_PLUGIN_STATE_DIRECTORY")
		if found {
			// If we get an error just look for the next possible location
			c, err = cache.GetCache(cachePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error trying NAGIOS_PLUGIN_STATE_DIRECTORY: %s\n", err)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "Using cache from path '%s' (ENV)\n", cachePath)
			}
		}
		if c == nil {
			c, err = cache.GetCache("/usr/local/nagios/var/")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error trying /usr/local/nagios/var/: %s\n", err)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "Using cache from path '%s'\n", "/usr/local/nagios/var/")
			}
		}
		if c == nil {
			c, err = cache.GetCache(os.TempDir())
			if err != nil {
				check.Unknownf("Unable to determine a usable cache path. Please provide one. Error: %s", err)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "Using cache from path '%s' (TEMP)\n", os.TempDir())
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
				if verbose {
					fmt.Fprintf(os.Stderr, "Want record %s\n", e2)
				}
			}
		} else {
			wantRecords[e] = false
			if verbose {
				fmt.Fprintf(os.Stderr, "Want record %s\n", e)
			}
		}
	}

	isProxied := false

	if !onlyDNS {
		var cfZone string

		cfToken, found := os.LookupEnv("CLOUDFLARE_API_TOKEN")
		if !found {
			check.Unknownf("You must set the CLOUDFLARE_API_TOKEN variable")
		}

		cfAPI := cloudflare.NewClient(
			option.WithAPIToken(cfToken),
		)

		err := c.LoadCloudflareIPList(ctx, cfAPI)
		if err != nil {
			check.Unknownf("Unable to load list of Cloudflare public IPs: %s", err.Error())
		} else if verbose {
			fmt.Fprintf(os.Stderr, "Loaded CF IP list (from cache or fresh)\n")
		}

		if f.IsSet("zone") {
			cfZone = f.String("zone")
		} else {
			cfZone = dns.GetDomainFromHostname(hostname)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "Checking CF Zone %s\n", cfZone)
		}

		records, err := c.GetCFZoneDNS(ctx, cfAPI, cfZone)
		if err != nil {
			check.Criticalf("Unable to query Cloudflare DNS records: %s", err.Error())
		} else if verbose {
			fmt.Fprintf(os.Stderr, "Got CF Zone\n")
		}

		var foundRecord []string
		for _, r := range records {
			// fmt.Fprintf(os.Stderr, "RECORD: %v\n", r)
			if r.Name == hostname {
				if verbose {
					fmt.Fprintf(os.Stderr, "Found record with matching name (%s; type %s)\n", r.Name, r.Type)
				}
				// If we are filtering by query type, skip if this is the wrong type
				// If we are not filtering by query type, the types we care about are A, AAAA, and CNAME
				if (len(queryType) > 0 && string(r.Type) != queryType) || (r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME") {
					if verbose {
						fmt.Fprintf(os.Stderr, "Skipping type that is not what we need\n")
					}
					continue
				}

				// Set this so we know what DNS record to expect
				// NOTE: The current behavior for multiple records with the same name
				//       is that if any of them is proxied they all are. This is probably
				//       undefined behavior but we will go with it for now.
				isProxied = isProxied || r.Proxied

				if len(wantRecords) > 0 {
					if _, ok := wantRecords[r.Content]; ok {
						if verbose {
							fmt.Fprintf(os.Stderr, "Found record we want (%s)\n", r.Content)
						}
						wantRecords[r.Content] = true
						foundRecord = append(foundRecord, r.Content)
					} else {
						check.AddResultf(nagiosplugin.CRITICAL, "Found unexpected DNS %s record: %s", r.Type, r.Content)
					}
				} else {
					if verbose {
						fmt.Fprintf(os.Stderr, "Found any valid record (%s)\n", r.Content)
					}
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
		path, err := exec.LookPath("dig")
		if err != nil {
			check.Unknownf("Could not find 'dig' command on PATH: %s", err.Error())
		}

		args := []string{"+short"}

		if f.IsSet("timeout") {
			args = append(args, "+time="+strconv.Itoa(f.Int("timeout")))
		}

		if f.IsSet("dns-server") {
			args = append(args, "@"+f.String("dns-server"))
		}

		if isProxied {
			// Do A and AAAA lookups and make sure they are inside the CF IP ranges
			// NOTE: Requires `DiG 9.x` for "Multiple Query" support
			args = append(args, hostname, "-t", "A", hostname, "-t", "AAAA")

			results, err := runCommand(path, args)
			if err != nil {
				check.Unknownf("Error running dig: %s", err)
			}

			if len(results) == 0 {
				check.Criticalf("No DNS A+AAAA records found")
			}

			for _, ipStr := range results {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					check.AddResultf(nagiosplugin.CRITICAL, "Failed to parse IP `%s`", ipStr)
				} else {
					found := false
					if ip.To4() == nil {
						for _, cidr := range c.PublicCIDRsV6 {
							if cidr.Contains(ip) {
								found = true
								break
							}
						}
					} else {
						for _, cidr := range c.PublicCIDRsV4 {
							if cidr.Contains(ip) {
								found = true
								break
							}
						}
					}

					if !found {
						check.AddResultf(nagiosplugin.CRITICAL, "IP `%s` does not belong to CloudFlare", ipStr)
					}
				}
			}
			// NOTE: We can add an "OK" here unconditionally because a CRITICAL will override it.
			check.AddResultf(nagiosplugin.OK, "Results: %s", strings.Join(results, ","))
		} else {
			// Do a regular DNS check
			args = append(args, hostname, "-t", queryType)

			results, err := runCommand(path, args)
			if err != nil {
				check.Unknownf("Error running dig: %s", err)
			}

			if len(expectedRaw) > 0 {
				if Equal(results, expectedRaw) {
					check.AddResultf(nagiosplugin.OK, "Results: %s", strings.Join(results, ","))
				} else {
					check.AddResultf(nagiosplugin.CRITICAL, "DNS lookup result different from expected\nExpected:\t%s\nGot:\t%s", expectedRaw, strings.Join(results, ","))
				}
			} else {
				check.AddResultf(nagiosplugin.OK, "Results: %s", strings.Join(results, ","))
			}
		}
	}

	if memP != nil {
		memP.Stop()
	}
}

func runCommand(path string, args []string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Executing `%s %s`\n", path, strings.Join(args, " "))
	cmd := exec.Command(path, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	results := strings.Split(strings.ReplaceAll(out.String(), "\r\n", "\n"), "\n")

	// If there is a blank last element, remove it
	if len(results) > 1 && len(results[len(results)-1]) == 0 {
		results = results[:len(results)-1]
	}

	for i := range results {
		s := results[i]
		sz := len(s)
		if sz > 0 && s[sz-1] == '.' {
			results[i] = s[:sz-1]
		}
	}
	sort.Strings(results)

	return results, nil
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
