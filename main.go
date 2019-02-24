package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-ini/ini"
)

const chRecName = "_acme-challenge"

func main() {
	// Get command-line flags
	cleanup := flag.Bool("cleanup", false, "Sets cleanup mode (to be used in --manual-cleanup-hook)")
	verbose := flag.Bool("verbose", false, "Enables verbose output")
	renewPath := flag.String("renew-path", "/etc/letsencrypt/renewal/", "Let's Encrypt renew folder path")
	saveRenewCreds := flag.Bool("save-renew-creds", false, "Save Cloudflare credentials to Let's Encrypt renew config?")
	onlySaveRenewCreds := flag.Bool("only-save-renew-creds", false, "Do nothing other than save Cloudflare credentials to Let's Encrypt renew config?")
	flag.Parse()

	if *onlySaveRenewCreds {
		*saveRenewCreds = true
	}

	// Get environment variables
	domain, ok := os.LookupEnv("CERTBOT_DOMAIN")
	if !ok {
		fmt.Println("[error] Environment variable CERTBOT_DOMAIN not set")
		return
	}
	vt, ok := os.LookupEnv("CERTBOT_VALIDATION")
	if !ok {
		fmt.Println("[error] Environment variable CERTBOT_VALIDATION not set")
		return
	}
	cfAPIEmail, ok := os.LookupEnv("CF_API_EMAIL")
	if !ok && *verbose {
		fmt.Println("[warning] Environment variable CF_API_EMAIL not set, now depending on renew config")
	}
	cfAPIKey, ok := os.LookupEnv("CF_API_KEY")
	if !ok && *verbose {
		fmt.Println("[warning] Environment variable CF_API_KEY not set, now depending on renew config")
	}

	// Get renewal file path
	renewDomain := domain
	var renewFilePath string
	for {
		renewFilePath = path.Join(*renewPath, renewDomain+".conf")
		if _, err := os.Stat(renewFilePath); err == nil {
			break
		}
		tldPos := strings.LastIndexByte(renewDomain, '.')
		sldPos := strings.IndexByte(renewDomain, '.')
		if sldPos == tldPos || sldPos == -1 {
			fmt.Println("[error] Certbot renewal file not found")
			return
		}
		renewDomain = renewDomain[sldPos+1:]
	}

	// Load API email and/or key from renewal file
	if cfAPIEmail == "" || cfAPIKey == "" {
		file, err := ini.Load(renewFilePath)
		if err != nil {
			fmt.Printf("[error] Failed to load file \"%s\"\n%v\n", renewFilePath, err)
			return
		}
		section := file.Section("go-certbot-cloudflare")
		if section == nil {
			fmt.Printf("[error] Could not find section \"go-certbot-cloudflare\" in file \"%s\"\n", renewFilePath)
			return
		}
		if cfAPIEmail == "" {
			keyAPIEmail := section.Key("cf_api_email")
			if keyAPIEmail == nil {
				fmt.Printf("[error] Could not find key \"cf_api_email\" under section \"go-certbot-cloudflare\" in file \"%s\"\n", renewFilePath)
				return
			}
			cfAPIEmail = keyAPIEmail.String()
		}
		if cfAPIKey == "" {
			keyAPIKey := section.Key("cf_api_key")
			if keyAPIKey == nil {
				fmt.Printf("[error] Could not find key \"cf_api_key\" under section \"go-certbot-cloudflare\" in file \"%s\"\n", renewFilePath)
				return
			}
			cfAPIKey = keyAPIKey.String()
		}
	}
	if cfAPIEmail == "" || cfAPIKey == "" {
		fmt.Println("[error] Cloudflare email or API key is empty")
		return
	}

	// Get zone information from Cloudflare API
	zonesRes := &cfListZonesResponse{}
	zoneDomain := domain
	for {
		if *verbose {
			fmt.Printf("[info] Looking up zone %s in Cloudflare account\n", zoneDomain)
		}
		httpRes, err := cfGet(cfAPIEmail, cfAPIKey, "zones", url.Values{
			"name":     []string{zoneDomain},
			"status":   []string{"active"},
			"page":     []string{"1"},
			"per_page": []string{"1"},
			"match":    []string{"all"},
		})
		if err != nil {
			fmt.Printf("[error] Cloudflare request failed\n%v\n", err)
			return
		}
		d := json.NewDecoder(httpRes.Body)
		if err = d.Decode(zonesRes); err != nil {
			fmt.Printf("[error] Failed to decode Cloudflare response\n%v\n", err)
			return
		}
		if !zonesRes.Success {
			fmt.Println("[error] Failed to look up zone")
			for i := range zonesRes.Errors {
				fmt.Println(zonesRes.Errors[i])
			}
			return
		}
		if len(zonesRes.Result) == 0 {
			if *verbose {
				fmt.Printf("[info] Zone \"%s\" not found in Cloudflare account, trying one subdomain less\n", zoneDomain)
			}
			tldPos := strings.LastIndexByte(zoneDomain, '.')
			sldPos := strings.IndexByte(zoneDomain, '.')
			if sldPos == tldPos || sldPos == -1 {
				fmt.Println("[error] Zone not found in Cloudflare account")
				return
			}
			zoneDomain = zoneDomain[sldPos+1:]
			zonesRes = &cfListZonesResponse{}
			continue
		}
		break
	}
	if len(zonesRes.Result[0].Nameservers) < 2 {
		fmt.Println("[error] Could not find two or more nameservers in zone")
		return
	}

	var subdomain string
	if len(domain) > 2 && domain[:2] == "*." {
		subdomain = chRecName + "." + domain[2:]
	} else {
		subdomain = chRecName + "." + domain
	}

	if *cleanup { // Cleanup mode
		// Get _acme-challenge TXT records from Cloudflare API
		if *verbose {
			fmt.Println("[info] Looking up DNS ACME challenge records in Cloudflare zone")
		}
		httpRes, err := cfGet(cfAPIEmail, cfAPIKey, "zones/"+zonesRes.Result[0].ID+"/dns_records", url.Values{
			"type":     []string{"TXT"},
			"name":     []string{subdomain},
			"page":     []string{"1"},
			"per_page": []string{"100"},
			"match":    []string{"all"},
		})
		recordsRes := &cfListRecordsResponse{}
		d := json.NewDecoder(httpRes.Body)
		if err = d.Decode(recordsRes); err != nil {
			fmt.Printf("[error] Failed to decode Cloudflare response\n%v\n", err)
			return
		}
		if len(recordsRes.Result) == 0 {
			if *verbose {
				fmt.Println("[info] No challenge records to clean up")
			}
			return
		}

		// Delete all _acme-challenge TXT records with Cloudflare API
		if *verbose {
			fmt.Printf("[info] Found %d challenge record(s) to clean up\n", len(recordsRes.Result))
		}
		for i := range recordsRes.Result {
			if *verbose {
				fmt.Printf("[info] Deleting challenge record TXT %s: \"%s\"\n", recordsRes.Result[i].Name, recordsRes.Result[i].Content)
			}
			httpRes, err := cfDelete(cfAPIEmail, cfAPIKey, "zones/"+zonesRes.Result[0].ID+"/dns_records/"+recordsRes.Result[i].ID, nil)
			if err != nil {
				fmt.Printf("[error] Cloudflare request failed\n%v\n", err)
				return
			}
			deleteRes := &cfDeleteRecordResponse{}
			d := json.NewDecoder(httpRes.Body)
			if err = d.Decode(deleteRes); err != nil {
				fmt.Printf("[error] Failed to decode Cloudflare response\n%v\n", err)
				return
			}
			if !deleteRes.Success {
				fmt.Println("[error] Failed to delete challenge record")
				for i := range deleteRes.Errors {
					fmt.Println(deleteRes.Errors[i])
				}
				return
			}
		}
	} else if !*onlySaveRenewCreds { // Auth/normal mode
		// Resolve IP of first nameserver
		addr1, err := net.ResolveUDPAddr("udp", zonesRes.Result[0].Nameservers[0]+":53")
		if err != nil {
			fmt.Printf("[error] Could not resolve nameserver in CF_NS1\n%v\n", err)
			return
		}
		rs1 := net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", addr1.String())
			},
		}

		// Resolve IP of second nameserver
		addr2, err := net.ResolveUDPAddr("udp", zonesRes.Result[0].Nameservers[1]+":53")
		if err != nil {
			fmt.Printf("[error] Could not resolve nameserver in CF_NS2\n%v\n", err)
			return
		}
		rs2 := net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", addr2.String())
			},
		}

		// Perform initial lookup of _acme-challenge TXT records using the Cloudflare DNS servers
		if *verbose {
			fmt.Printf("[info] Attempting initial lookup TXT %s\n", subdomain)
		}
		dnsRes, err := lookupCompareTXT(rs1, rs2, subdomain)
		if err == nil && strSliceLookup(dnsRes, vt) {
			if *verbose {
				fmt.Println("[info] Expected challenge record already exists on domain")
			}
			return
		}

		// If initial lookup could not find records,
		// create _acme-challenge TXT records using the Cloudflare API.
		if *verbose {
			fmt.Println("[info] Challenge record not found on domain")
			fmt.Printf("[info] Creating TXT record %s with content \"%s\"\n", subdomain, vt)
		}
		httpRes, err := cfPostJSON(cfAPIEmail, cfAPIKey, "zones/"+zonesRes.Result[0].ID+"/dns_records", &cfCreateDNSRecord{
			Type:    "TXT",
			Name:    subdomain,
			Content: vt,
		})
		if err != nil {
			fmt.Printf("[error] Cloudflare request failed\n%v\n", err)
			return
		}
		createRes := &cfCreateRecordResponse{}
		d := json.NewDecoder(httpRes.Body)
		if err = d.Decode(createRes); err != nil {
			fmt.Printf("[error] Failed to decode Cloudflare response\n%v\n", err)
			return
		}
		if !createRes.Success {
			fmt.Println("[error] Failed to create challenge record")
			for i := range createRes.Errors {
				fmt.Println(createRes.Errors[i])
			}
			return
		}

		// Wait for new _acme-challenge TXT record to update on Cloudflare nameservers
		if *verbose {
			fmt.Printf("[info] Attempting lookup TXT %s\n", subdomain)
		}
		dnsRes = nil
		attempts := 0
		for {
			attempts++
			if attempts > 30 {
				fmt.Println("[error] Did not find expected challenge record, gave up after 30 attempts")
				return
			}
			dnsRes, err = lookupCompareTXT(rs1, rs2, subdomain)
			if err == errInconsistent {
				if *verbose {
					fmt.Println(err.Error())
				}
				time.Sleep(1 * time.Second)
				continue
			} else if err != nil && !strings.Contains(err.Error(), "no such host") {
				fmt.Printf("[error] Failed lookup TXT %s\n%v\n", subdomain, err)
				return
			}
			if dnsRes == nil || len(dnsRes) == 0 || !strSliceLookup(dnsRes, vt) {
				if *verbose {
					fmt.Printf("[info] Challenge record \"%s\" missing from domain, retrying...\n", vt)
				}
				time.Sleep(1 * time.Second)
				continue
			}
			break
		}
		if *verbose {
			fmt.Printf("[info] Found expected challenge record after %d attempt(s)\n", attempts)
		}
	}

	// Save Cloudflare credentials to Let's Encrypt renew config
	if *saveRenewCreds {
		file, err := ini.Load(renewFilePath)
		if err != nil {
			fmt.Printf("[error] Failed to load file \"%s\"\n%v\n", renewFilePath, err)
			return
		}
		file.DeleteSection("go-certbot-cloudflare")
		section, err := file.NewSection("go-certbot-cloudflare")
		if err != nil {
			fmt.Println("[error] Failed to create section \"go-certbot-cloudflare\"")
			return
		}
		if _, err = section.NewKey("cf_api_email", cfAPIEmail); err != nil {
			fmt.Println("[error] Failed to create key \"cf_api_email\" in section \"go-certbot-cloudflare\"")
			return
		}
		if _, err = section.NewKey("cf_api_key", cfAPIKey); err != nil {
			fmt.Println("[error] Failed to create key \"cf_api_key\" in section \"go-certbot-cloudflare\"")
			return
		}
		if err = file.SaveTo(renewFilePath); err != nil {
			fmt.Printf("[error] Failed to save file \"%s\"\n", renewFilePath)
			return
		}
	}
}
