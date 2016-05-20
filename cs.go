/*
Package gocs is a library implementing the CrowdStrike Intel API v2.0

Written by Slavik Markovich at Demisto
*/
package gocs

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL    = "https://intelapi.crowdstrike.com/" // DefaultURL is the URL for the API endpoint
	AuthHeaderID  = "X-CSIX-CUSTID"                     // AuthHeaderID for the API
	AuthHeaderKey = "X-CSIX-CUSTKEY"                    // AuthHeaderKey for the API
	AllFields     = "__full__"                          // AllFields should be returned from the query
	BasicFields   = "__basic__"                         // BasicFields should be returned from the query
)

// Error structs are returned from this library for known error conditions
type Error struct {
	ID      string `json:"id"`      // ID of the error
	Details string `json:"details"` // Details of the error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.ID, e.Details)
}

var (
	// ErrMissingCredentials is returned when API key is missing
	ErrMissingCredentials = &Error{ID: "missing_credentials", Details: "You must provide the CrowsStrike API ID and key"}
	ErrMissingParams      = &Error{ID: "missing_parameters", Details: "You must provide the CrowsStrike API required parameters for the request"}
)

// Client interacts with the services provided by CrowdStrike.
type Intel struct {
	id       string       // The API ID
	key      string       // The API key
	url      string       // CS URL
	errorlog *log.Logger  // Optional logger to write errors to
	tracelog *log.Logger  // Optional logger to write trace and debug data to
	c        *http.Client // The client to use for requests
}

// OptionFunc is a function that configures a Client.
// It is used in New
type OptionFunc func(*Intel) error

// errorf logs to the error log.
func (c *Intel) errorf(format string, args ...interface{}) {
	if c.errorlog != nil {
		c.errorlog.Printf(format, args...)
	}
}

// tracef logs to the trace log.
func (c *Intel) tracef(format string, args ...interface{}) {
	if c.tracelog != nil {
		c.tracelog.Printf(format, args...)
	}
}

// New creates a new CS client.
//
// The caller can configure the new client by passing configuration options to the func.
//
// Example:
//
//   client, err := gocs.New(
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
func New(options ...OptionFunc) (*Intel, error) {
	// Set up the client
	c := &Intel{
		url: DefaultURL,
		c:   http.DefaultClient,
	}

	// Run the options on it
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	c.tracef("Using URL [%s]\n", c.url)

	if c.id == "" || c.key == "" {
		c.errorf("Missing credentials")
		return nil, ErrMissingCredentials
	}
	return c, nil
}

// Initialization functions

// SetCredentials sets the CS API key
// To receive a key, login to the portal at https://intel.crowdstrike.com and go to the "CrowdStrike API" tab
func SetCredentials(id, key string) OptionFunc {
	return func(c *Intel) error {
		if id == "" || key == "" {
			c.errorf("%v\n", ErrMissingCredentials)
			return ErrMissingCredentials
		}
		c.id, c.key = id, key
		return nil
	}
}

// SetHTTPClient can be used to specify the http.Client to use when making
// HTTP requests to Infinity API.
func SetHTTPClient(httpClient *http.Client) OptionFunc {
	return func(c *Intel) error {
		if httpClient != nil {
			c.c = httpClient
		} else {
			c.c = http.DefaultClient
		}
		return nil
	}
}

// SetURL defines the URL endpoint for Infinity
func SetURL(rawurl string) OptionFunc {
	return func(c *Intel) error {
		if rawurl == "" {
			rawurl = DefaultURL
		}
		u, err := url.Parse(rawurl)
		if err != nil {
			c.errorf("Invalid URL [%s] - %v\n", rawurl, err)
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			err := &Error{ID: "bad_url", Details: fmt.Sprintf("Invalid schema specified [%s]", rawurl)}
			c.errorf("%v", err)
			return err
		}
		c.url = rawurl
		if !strings.HasSuffix(c.url, "/") {
			c.url += "/"
		}
		return nil
	}
}

// SetErrorLog sets the logger for critical messages. It is nil by default.
func SetErrorLog(logger *log.Logger) func(*Intel) error {
	return func(c *Intel) error {
		c.errorlog = logger
		return nil
	}
}

// SetTraceLog specifies the logger to use for output of trace messages like
// HTTP requests and responses. It is nil by default.
func SetTraceLog(logger *log.Logger) func(*Intel) error {
	return func(c *Intel) error {
		c.tracelog = logger
		return nil
	}
}

// dumpRequest dumps a request to the debug logger if it was defined
func (c *Intel) dumpRequest(req *http.Request) {
	if c.tracelog != nil {
		out, err := httputil.DumpRequestOut(req, false)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// dumpResponse dumps a response to the debug logger if it was defined
func (c *Intel) dumpResponse(resp *http.Response) {
	if c.tracelog != nil {
		out, err := httputil.DumpResponse(resp, true)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// Request handling functions

// handleError will handle responses with status code different from success
func (c *Intel) handleError(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if c.errorlog != nil {
			out, err := httputil.DumpResponse(resp, true)
			if err == nil {
				c.errorf("%s\n", string(out))
			}
		}
		msg := fmt.Sprintf("Unexpected status code: %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
		c.errorf(msg)
		return &Error{ID: "http_error", Details: msg}
	}
	return nil
}

// do executes the API request.
// Returns the response if the status code is between 200 and 299
// `body` is an optional body for the POST requests.
func (c *Intel) do(method, rawurl string, params url.Values, body io.Reader, result interface{}) error {
	if len(params) > 0 {
		rawurl += "?" + params.Encode()
	}

	req, err := http.NewRequest(method, c.url+rawurl, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(AuthHeaderID, c.id)
	req.Header.Set(AuthHeaderKey, c.key)
	var t time.Time
	if c.tracelog != nil {
		c.dumpRequest(req)
		t = time.Now()
		c.tracef("Start request %s at %v", rawurl, t)
	}
	resp, err := c.c.Do(req)
	if c.tracelog != nil {
		c.tracef("End request %s at %v - took %v", rawurl, time.Now(), time.Since(t))
	}
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err = c.handleError(resp); err != nil {
		return err
	}
	c.dumpResponse(resp)
	if result != nil {
		switch result := result.(type) {
		// Should we just dump the response body
		case io.Writer:
			if _, err = io.Copy(result, resp.Body); err != nil {
				return err
			}
		default:
			if err = json.NewDecoder(resp.Body).Decode(result); err != nil {
				if c.errorlog != nil {
					out, err := httputil.DumpResponse(resp, true)
					if err == nil {
						c.errorf("%s\n", string(out))
					}
				}
				return err
			}
		}
	}
	return nil
}

// Structs

// SortField ...
type SortField struct {
	Name      string `json:"name"`
	Ascending bool   `json:"ascending"`
}

// ActorRequest to return actors based on query parameters that will be AND'ed between them
type ActorRequest struct {
	Q                    string      `json:"q"`
	Name                 string      `json:"name"`
	Description          string      `json:"description"`
	MinLastModifiedDate  *time.Time  `json:"min_last_modified_date"`
	MaxLastModifieldDate *time.Time  `json:"max_last_modified_date"`
	MinLastActivityDate  *time.Time  `json:"min_last_activity_date"`
	MaxLastActivityDate  *time.Time  `json:"max_last_activity_date"`
	Origins              []string    `json:"origins"`
	TargetCountries      []string    `json:"target_countries"`
	TargetIndustries     []string    `json:"target_industries"`
	Motivations          []string    `json:"motivations"`
	Fields               []string    `json:"fields"` // Fields requested in the reply. Can receive gocs.AllFields and gocs.BasicFields
	SortFields           []SortField `json:"sort"`
	Offset               int         `json:"offset"`
	Limit                int         `json:"limit"`
}

// Slugable ...
type Slugable struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
	Slug  string `json:"slug"`
}

// Resource for an actor
type Resource struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	ShortDescription   string `json:"short_description"`
	KnownAs            string `json:"known_as"`
	CreatedDate        time.Time
	CreatedEpoch       float64    `json:"created_date"`
	TargetIndustries   []Slugable `json:"target_industries"`
	LastModifiedDate   time.Time
	LastModifiedEpoch  float64    `json:"last_modified_date"`
	TargetCountries    []Slugable `json:"target_countries"`
	FirstActivityDate  time.Time
	FirstActivityEpoch float64 `json:"first_activity_date"`
	LastActivityDate   time.Time
	LastActivityEpoch  float64    `json:"last_activity_date"`
	URL                string     `json:"url"`
	Motivations        []Slugable `json:"motivations"`
	Origins            []Slugable `json:"origins"`
	Slug               string     `json:"slug"`
}

func (r *Resource) convertDates() {
	r.CreatedDate = time.Unix(int64(r.CreatedEpoch), 0)
	r.LastActivityDate = time.Unix(int64(r.LastActivityEpoch), 0)
	r.FirstActivityDate = time.Unix(int64(r.FirstActivityEpoch), 0)
	r.LastActivityDate = time.Unix(int64(r.LastActivityEpoch), 0)
}

// ActorResponse for the ActorRequest
type ActorResponse struct {
	Meta struct {
		Paging struct {
			Total  int `json:"total"`
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		} `json:"paging"`
	} `json:"meta"`
	QueryTime float64    `json:"query_time"`
	Resources []Resource `json:"resources"`
}

// IndicatorRequest searches for an indicator based on the parameter and relevant filter
type IndicatorRequest struct {
	Parameter string    `json:"parameter"`
	Filter    string    `json:"filter"`
	Value     string    `json:"value"`
	Sort      SortField `json:"sort"`
	Page      int       `json:"page"`
	PerPage   int       `json:"perPage"`
}

// Relation to indicator
type Relation struct {
	Indicator          string  `json:"indicator"`
	Type               string  `json:"type"`
	CreatedDateEpoch   float64 `json:"created_date"`
	CreatedDate        time.Time
	LastValidDateEpoch float64 `json:"last_valid_date"`
	LastValidDate      time.Time
}

func (r *Relation) convertDates() {
	r.CreatedDate = time.Unix(int64(r.CreatedDateEpoch), 0)
	r.LastValidDate = time.Unix(int64(r.LastValidDateEpoch), 0)
}

// Label for an indicator
type Label struct {
	Name string `json:"name"`
	CreatedOnEpoch float64 `json:"created_on"`
	CreatedOn time.Time
	LastValidOnEpoch float64 `json:"last_valid_on"`
	LastValidOn time.Time
}

func (l *Label) convertDates() {
	l.CreatedOn = time.Unix(int64(l.CreatedOnEpoch), 0)
	l.LastValidOn = time.Unix(int64(l.LastValidOnEpoch), 0)
}

// IndicatorResponse for the request
type IndicatorResponse struct {
	Indicator           string  `json:"indicator"`
	Type                string  `json:"type"`
	LastUpdatedEpoch    float64 `json:"last_updated"`
	LastUpdated         time.Time
	PublishedDateEpoch  float64 `json:"published_date"`
	PublishedDate       time.Time
	MaliciousConfidence string     `json:"malicious_confidence"`
	Reports             []string   `json:"reports"`
	Actors              []string   `json:"actors"`
	MalwareFamilies     []string   `json:"malware_families"`
	KillChains          []string   `json:"kill_chains"`
	DomainTypes         []string   `json:"domain_types"`
	IPAddressTypes      []string   `json:"ip_address_types"`
	Relations           []Relation `json:"relations"`
	Labels []Label `json:"labels"`
}

func (ir *IndicatorResponse) convertDates() {
	ir.LastUpdated = time.Unix(int64(ir.LastUpdatedEpoch), 0)
	ir.PublishedDate = time.Unix(int64(ir.PublishedDateEpoch), 0)
	for i := range ir.Relations {
		ir.Relations[i].convertDates()
	}
	for i := range ir.Labels {
		ir.Labels[i].convertDates()
	}
}

func addString(name, val string, params url.Values) {
	if val != "" {
		params.Add(name, val)
	}
}

func addTime(name string, t *time.Time, params url.Values) {
	if t != nil && !t.IsZero() {
		params.Add(name, strconv.FormatInt(t.Unix(), 10))
	}
}

func addStringArr(name string, val []string, params url.Values) {
	for _, v := range val {
		addString(name, v, params)
	}
}

func addSortFields(name string, sortFields []SortField, params url.Values) {
	for i := range sortFields {
		val := sortFields[i].Name + "."
		if sortFields[i].Ascending {
			val += "asc"
		} else {
			val += "desc"
		}
		addString(name, val, params)
	}
}

func addInt(name string, val int, params url.Values) {
	addString(name, strconv.Itoa(val), params)
}

func actorRequestToParams(req *ActorRequest) url.Values {
	if req.Limit == 0 {
		req.Limit = 10
	}
	if len(req.Fields) == 0 {
		req.Fields = append(req.Fields, BasicFields)
	}
	params := url.Values{}
	addString("q", req.Q, params)
	addString("name", req.Name, params)
	addString("description", req.Description, params)
	addTime("min_last_modified_date", req.MinLastModifiedDate, params)
	addTime("max_last_modified_date", req.MaxLastModifieldDate, params)
	addTime("min_last_activity_date", req.MinLastActivityDate, params)
	addTime("max_last_activity_date", req.MaxLastActivityDate, params)
	addStringArr("origins", req.Origins, params)
	addStringArr("target_countries", req.TargetCountries, params)
	addStringArr("target_industries", req.TargetIndustries, params)
	addStringArr("motivations", req.Motivations, params)
	addStringArr("motivations", req.Motivations, params)
	addStringArr("fields", req.Fields, params)
	addSortFields("sort", req.SortFields, params)
	addInt("offset", req.Offset, params)
	addInt("limit", req.Limit, params)
	return params
}

// Public API functions

// Actors will query the actors API
func (c *Intel) Actors(req *ActorRequest) (resp *ActorResponse, err error) {
	resp = &ActorResponse{}
	params := actorRequestToParams(req)
	err = c.do("GET", "actor/v1/queries/actors", params, nil, &resp)
	if err == nil {
		for i := range resp.Resources {
			resp.Resources[i].convertDates()
		}
	}
	return
}

// ActorsJSON will write the response to the given writer
func (c *Intel) ActorsJSON(req *ActorRequest, w io.Writer) (err error) {
	params := actorRequestToParams(req)
	err = c.do("GET", "actor/v1/queries/actors", params, nil, w)
	return
}

func indicatorRequestToParams(req *IndicatorRequest) url.Values {
	params := url.Values{req.Filter: {req.Value}}
	if req.Sort.Name != "" {
		order := "desc"
		if req.Sort.Ascending {
			order = "asc"
		}
		params.Add("sort", req.Sort.Name)
		params.Add("order", order)
	}
	if req.Page == 0 {
		req.Page = 1
	}
	if req.PerPage == 0 {
		req.PerPage = 10
	}
	params.Add("page", strconv.Itoa(req.Page))
	params.Add("perPage", strconv.Itoa(req.PerPage))
	return params
}

// Indicators will query the indicators API
func (c *Intel) Indicators(req *IndicatorRequest) (resp []IndicatorResponse, err error) {
	if req.Parameter == "" || req.Filter == "" || req.Value == "" {
		return nil, ErrMissingParams
	}
	resp = []IndicatorResponse{}
	params := indicatorRequestToParams(req)
	err = c.do("GET", "indicator/v1/search/"+req.Parameter, params, nil, &resp)
	if err == nil {
		for i := range resp {
			resp[i].convertDates()
		}
	}
	return
}

// IndicatorsJSON will write the response to the given writer
func (c *Intel) IndicatorsJSON(req *IndicatorRequest, w io.Writer) (err error) {
	if req.Parameter == "" || req.Filter == "" || req.Value == "" {
		return ErrMissingParams
	}
	params := indicatorRequestToParams(req)
	err = c.do("GET", "indicator/v1/search/"+req.Parameter, params, nil, w)
	return
}
