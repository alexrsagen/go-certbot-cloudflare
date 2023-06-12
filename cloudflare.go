package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
)

const cfAPIBase = "https://api.cloudflare.com/client/v4/"

type cfCreateDNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      uint32 `json:"ttl,omitempty"`
	Priority uint16 `json:"priority,omitempty"`
	Proxied  bool   `json:"proxied,omitempty"`
}

type cfResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResponseOwner struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	OwnerType string `json:"owner_type"`
}

type cfResponsePlan struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Price        int    `json:"price"`
	Currency     string `json:"currency"`
	Frequency    string `json:"frequency"`
	LegacyID     string `json:"legacy_id"`
	IsSubscribed bool   `json:"is_subscribed"`
	CanSubscribe bool   `json:"can_subscribe"`
}

type cfResponseZone struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	DevelopmentMode     int             `json:"development_mode"`
	OriginalNameservers []string        `json:"original_name_servers"`
	OriginalRegistrar   string          `json:"original_registrar"`
	OriginalDNSHost     string          `json:"original_dns_host"`
	CreatedOn           string          `json:"created_on"`
	ModifiedOn          string          `json:"modified_on"`
	Owner               cfResponseOwner `json:"owner"`
	Permissions         []string        `json:"permissions"`
	Plan                cfResponsePlan  `json:"plan"`
	PlanPending         cfResponsePlan  `json:"plan_pending"`
	Status              string          `json:"status"`
	Paused              bool            `json:"paused"`
	Type                string          `json:"type"`
	Nameservers         []string        `json:"name_servers"`
}

type cfResponseRecordID struct {
	ID string `json:"id"`
}

type cfResponseRecord struct {
	cfResponseRecordID
	Type       string `json:"type"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	Proxiable  bool   `json:"proxiable"`
	Proxied    bool   `json:"proxied"`
	TTL        int    `json:"ttl"`
	Locked     bool   `json:"locked"`
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	CreatedOn  string `json:"created_on"`
	ModifiedOn string `json:"modified_on"`
}

type cfResponseResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

type cfListZonesResponse struct {
	Success    bool                 `json:"success"`
	Errors     []cfResponseError    `json:"errors"`
	Result     []cfResponseZone     `json:"result"`
	ResultInfo cfResponseResultInfo `json:"result_info"`
}

type cfListRecordsResponse struct {
	Success    bool                 `json:"success"`
	Errors     []cfResponseError    `json:"errors"`
	Result     []cfResponseRecord   `json:"result"`
	ResultInfo cfResponseResultInfo `json:"result_info"`
}

type cfDeleteRecordResponse struct {
	Success bool               `json:"success"`
	Errors  []cfResponseError  `json:"errors"`
	Result  cfResponseRecordID `json:"result"`
}

type cfCreateRecordResponse struct {
	Success bool              `json:"success"`
	Errors  []cfResponseError `json:"errors"`
	Result  cfResponseRecord  `json:"result"`
}

func cfGet(apiAccessToken, apiEmail, apiKey, urlExt string, v url.Values) (*http.Response, error) {
	base, err := url.Parse(cfAPIBase)
	if err != nil {
		return nil, err
	}
	ext, err := url.Parse(urlExt)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", base.ResolveReference(ext).String(), nil)
	if err != nil {
		return nil, err
	}
	if v != nil {
		req.URL.RawQuery = v.Encode()
	}
	req.Header.Set("Content-Type", "application/json")
	if apiAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiAccessToken)
	} else {
		req.Header.Set("X-Auth-Email", apiEmail)
		req.Header.Set("X-Auth-Key", apiKey)
	}
	return http.DefaultClient.Do(req)
}

func cfDelete(apiAccessToken, apiEmail, apiKey, urlExt string, v url.Values) (*http.Response, error) {
	base, err := url.Parse(cfAPIBase)
	if err != nil {
		return nil, err
	}
	ext, err := url.Parse(urlExt)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("DELETE", base.ResolveReference(ext).String(), nil)
	if err != nil {
		return nil, err
	}
	if v != nil {
		req.URL.RawQuery = v.Encode()
	}
	req.Header.Set("Content-Type", "application/json")
	if apiAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiAccessToken)
	} else {
		req.Header.Set("X-Auth-Email", apiEmail)
		req.Header.Set("X-Auth-Key", apiKey)
	}
	return http.DefaultClient.Do(req)
}

func cfPostJSON(apiAccessToken, apiEmail, apiKey, urlExt string, v interface{}) (*http.Response, error) {
	base, err := url.Parse(cfAPIBase)
	if err != nil {
		return nil, err
	}
	ext, err := url.Parse(urlExt)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", base.ResolveReference(ext).String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiAccessToken)
	} else {
		req.Header.Set("X-Auth-Email", apiEmail)
		req.Header.Set("X-Auth-Key", apiKey)
	}
	return http.DefaultClient.Do(req)
}
