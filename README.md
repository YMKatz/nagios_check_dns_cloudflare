# check_dns_cloudflare for Nagios

This tool checks CloudFlare DNS entries using the CloudFlare API and then checks that the DNS record resolves to known CloudFlare IPs (as determined by CloudFlare's [official list](https://www.cloudflare.com/ips/)).

This tools uses a cache directory located at one of the following locations (in order):

- `NAGIOS_PLUGIN_STATE_DIRECTORY` envvar
- `/usr/local/nagios/var`, if it exists
- `$TEMP`

Cache implementation is loosely based on [Nagios-Plugins state retention](https://nagios-plugins.org/doc/state-retention.html).
