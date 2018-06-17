package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const chRecName = "_acme-challenge"

func main() {
	// Get environment variables
	cfAPIEmail, ok := os.LookupEnv("CF_API_EMAIL")
	if !ok {
		fmt.Println("[error] Environment variable CF_API_EMAIL not set")
		return
	}
	cfAPIKey, ok := os.LookupEnv("CF_API_KEY")
	if !ok {
		fmt.Println("[error] Environment variable CF_API_KEY not set")
		return
	}
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

	// Get command-line flags
	cleanup := flag.Bool("cleanup", false, "Sets cleanup mode (to be used in --manual-cleanup-hook)")
	verbose := flag.Bool("verbose", false, "Enables verbose output")
	flag.Parse()

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
			fmt.Println("[error] Zone not found in Cloudflare account")
			tldPos := strings.LastIndexByte(zoneDomain, '.')
			sldPos := strings.IndexByte(zoneDomain, '.')
			if sldPos == tldPos || sldPos == -1 {
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

	subdomain := chRecName + "." + zoneDomain

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
	} else { // Auth/normal mode
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
			Name:    chRecName,
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
				fmt.Println(err.Error())
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
}
