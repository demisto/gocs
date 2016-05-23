/*
Package gocs is a library implementing the CrowdStrike Intel API v2.0

Written by Slavik Markovich at Demisto
*/
package gocs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultURLHost is the URL for the host API endpoint
	DefaultURLHost = "https://falconapi.crowdstrike.com/"
)

// Host interacts with the services provided by CrowdStrike Falcon Host API.
type Host struct {
	*client
}

// NewHost creates a new CS client.
//
// The caller can configure the new client by passing configuration options to the func.
//
// Example:
//
//   client, err := gocs.NewHost(
//     gocs.SetCredentials("id", "key"),
//     gocs.SetUrl("https://some.url.com:port/"),
//     gocs.SetErrorLog(log.New(os.Stderr, "CS: ", log.Lshortfile))
//
// If no URL is configured, Client uses DefaultURL by default.
//
// If no HttpClient is configured, then http.DefaultClient is used.
// You can use your own http.Client with some http.Transport for advanced scenarios.
//
// An error is also returned when some configuration option is invalid.
func NewHost(options ...OptionFunc) (*Host, error) {
	options = append([]OptionFunc{SetURL(DefaultURLHost)}, options...)
	// Set up the client
	c, err := newClient(options...)
	if err != nil {
		return nil, err
	}
	return &Host{client: c}, nil
}

// Structs

// SearchIOCsRequest ...
type SearchIOCsRequest struct {
	Types                   []string   `json:"types"`
	Values                  []string   `json:"values"`
	Policies                []string   `json:"policies"`
	ShareLevels             []string   `json:"share_levels"`
	Sources                 []string   `json:"sources"`
	FromExpirationTimestamp *time.Time `json:"fromExpirationTimestamp"`
	ToExpirationTimestamp   *time.Time `json:"toExpirationTimestamp"`
	Sort                    *SortField `json:"sort"`
	Paging
}

// SearchIOCsResponse ...
type SearchIOCsResponse struct {
	Meta struct {
		QueryTime  float64 `json:"query_time"`
		Pagination struct {
			Total  int `json:"total"`
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		} `json:"pagination"`
		TraceID string `json:"trace_id"`
		Entity  string `json:"entity"`
	} `json:"meta"`
	Resources []string `json:"resources"`
	Errors    []Error  `json:"errors"`
}

// DeviceCountResponse ...
type DeviceCountResponse struct {
	Meta struct {
		QueryTime float64 `json:"query_time"`
		TraceID   string  `json:"trace_id"`
	} `json:"meta"`
	Resources []struct {
		DeviceCount int `json:"device_count"`
	} `json:"resources"`
	Errors []Error `json:"errors"`
}

// Process holds the information about a detected process
type Process struct {
	DeviceID            string `json:"device_id"`
	CommandLine         string `json:"command_line"`
	ProcessID           string `json:"process_id"`
	ProcessIDLocal      string `json:"process_id_local"`
	FileName            string `json:"file_name"`
	StartTimestamp      time.Time
	StartTimestampEpoch float64 `json:"start_timestamp_raw"`
	StopTimestamp       time.Time
	StopTimestampEpoch  float64 `json:"stop_timestamp_raw"`
}

// IOC ...
type IOC struct {
	Type           string `json:"type,omitempty"`
	Value          string `json:"value,omitempty"`
	Policy         string `json:"policy,omitempty"`
	ShareLevel     string `json:"shareLevel,omitempty"`
	ExpirationDays int    `json:"expiration_days,omitempty"`
	Source         string `json:"source,omitempty"`
	Description    string `json:"description,omitempty"`
}

// ProcessResponse ...
type ProcessResponse struct {
	Meta struct {
		QueryTime float64 `json:"query_time"`
		TraceID   string  `json:"trace_id"`
	} `json:"meta"`
	Resources []Process `json:"resources"`
	Errors    []Error   `json:"errors"`
}

// ResolveResponse ...
type ResolveResponse struct {
	Meta struct {
		QueryTime float64 `json:"query_time"`
		TraceID   string  `json:"trace_id"`
		Writes    struct {
			ResourcesAffected int `json:"resources_affected"`
		} `json:"writes"`
	} `json:"meta"`
	Errors []Error `json:"errors"`
}

func addRFCTime(name string, t *time.Time, params url.Values) {
	if t != nil {
		params.Add(name, t.Format(time.RFC3339))
	}
}

func searchRequestToParams(req *SearchIOCsRequest) url.Values {
	params := url.Values{}
	addStringArr("types", req.Types, params)
	addStringArr("values", req.Values, params)
	addStringArr("policies", req.Policies, params)
	addStringArr("share_levels", req.ShareLevels, params)
	addStringArr("sources", req.Sources, params)
	addRFCTime("from.expiration_timestamp", req.FromExpirationTimestamp, params)
	addRFCTime("to.expiration_timestamp", req.ToExpirationTimestamp, params)
	if req.Sort != nil {
		addSortFields("sort", []SortField{*req.Sort}, params)
	}
	if req.Limit != 0 {
		addInt("limit", req.Limit, params)
	}
	if req.Offset != 0 {
		addInt("offset", req.Offset, params)
	}
	return params
}

func (h *Host) authFunc() func(*http.Request) {
	return func(req *http.Request) {
		req.SetBasicAuth(h.id, h.key)
	}
}

// SearchIOCs ...
func (h *Host) SearchIOCs(req *SearchIOCsRequest) (resp *SearchIOCsResponse, err error) {
	resp = &SearchIOCsResponse{}
	params := searchRequestToParams(req)
	err = h.do("GET", "indicators/queries/iocs/v1", params, nil, resp, h.authFunc())
	return
}

// SearchIOCsJSON ...
func (h *Host) SearchIOCsJSON(req *SearchIOCsRequest, w io.Writer) (err error) {
	params := searchRequestToParams(req)
	err = h.do("GET", "indicators/queries/iocs/v1", params, nil, w, h.authFunc())
	return
}

// DeviceCount ...
func (h *Host) DeviceCount(t, v string) (resp *DeviceCountResponse, err error) {
	resp = &DeviceCountResponse{}
	params := url.Values{"type": {t}, "value": {v}}
	err = h.do("GET", "indicators/aggregates/devices-count/v1", params, nil, resp, h.authFunc())
	return
}

// DeviceCountJSON ...
func (h *Host) DeviceCountJSON(t, v string, w io.Writer) (err error) {
	params := url.Values{"type": {t}, "value": {v}}
	err = h.do("GET", "indicators/aggregates/devices-count/v1", params, nil, w, h.authFunc())
	return
}

// DevicesRanOn ...
func (h *Host) DevicesRanOn(t, v string) (resp *SearchIOCsResponse, err error) {
	resp = &SearchIOCsResponse{}
	params := url.Values{"type": {t}, "value": {v}}
	err = h.do("GET", "indicators/queries/devices/v1", params, nil, resp, h.authFunc())
	return
}

// DevicesRanOnJSON ...
func (h *Host) DevicesRanOnJSON(t, v string, w io.Writer) (err error) {
	params := url.Values{"type": {t}, "value": {v}}
	err = h.do("GET", "indicators/queries/devices/v1", params, nil, w, h.authFunc())
	return
}

// ProcessesRanOn ...
func (h *Host) ProcessesRanOn(t, v, device string) (resp *SearchIOCsResponse, err error) {
	resp = &SearchIOCsResponse{}
	params := url.Values{"type": {t}, "value": {v}, "device_id": {device}}
	err = h.do("GET", "indicators/queries/processes/v1", params, nil, resp, h.authFunc())
	return
}

// ProcessesRanOnJSON ...
func (h *Host) ProcessesRanOnJSON(t, v, device string, w io.Writer) (err error) {
	params := url.Values{"type": {t}, "value": {v}, "device_id": {device}}
	err = h.do("GET", "indicators/queries/processes/v1", params, nil, w, h.authFunc())
	return
}

// ProcessDetails ...
func (h *Host) ProcessDetails(ids []string) (resp *ProcessResponse, err error) {
	resp = &ProcessResponse{}
	params := url.Values{}
	addStringArr("ids", ids, params)
	err = h.do("GET", "processes/entities/processes/v1", params, nil, resp, h.authFunc())
	return
}

// ProcessDetailsJSON ...
func (h *Host) ProcessDetailsJSON(ids []string, w io.Writer) (err error) {
	params := url.Values{}
	addStringArr("ids", ids, params)
	err = h.do("GET", "processes/entities/processes/v1", params, nil, w, h.authFunc())
	return
}

// UploadIOCs ...
func (h *Host) UploadIOCs(iocs []IOC) (resp *SearchIOCsResponse, err error) {
	resp = &SearchIOCsResponse{}
	var b bytes.Buffer
	err = json.NewEncoder(&b).Encode(iocs)
	if err != nil {
		return
	}
	err = h.do("POST", "indicators/entities/iocs/v1", nil, &b, resp, h.authFunc())
	return
}

// UpdateIOCs ...
func (h *Host) UpdateIOCs(ids []string, ioc *IOC) (resp *SearchIOCsResponse, err error) {
	if ioc == nil {
		return nil, ErrMissingParams
	}
	resp = &SearchIOCsResponse{}
	params := url.Values{}
	addStringArr("ids", ids, params)
	var b bytes.Buffer
	err = json.NewEncoder(&b).Encode(ioc)
	if err != nil {
		return
	}
	err = h.do("PATCH", "indicators/entities/iocs/v1", params, &b, resp, h.authFunc())
	return
}

// DeleteIOCs ...
func (h *Host) DeleteIOCs(ids []string) (resp *SearchIOCsResponse, err error) {
	resp = &SearchIOCsResponse{}
	params := url.Values{}
	addStringArr("ids", ids, params)
	err = h.do("DELETE", "indicators/entities/iocs/v1", params, nil, resp, h.authFunc())
	return
}

// Resolve ...
func (h *Host) Resolve(ids []string, toState string) (resp *ResolveResponse, err error) {
	resp = &ResolveResponse{}
	params := url.Values{}
	addStringArr("ids", ids, params)
	addString("to_status", toState, params)
	err = h.do("PATCH", "detects/entities/detects/v1", params, nil, resp, h.authFunc())
	return
}
