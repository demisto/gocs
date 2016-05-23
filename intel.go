/*
Package gocs is a library implementing the CrowdStrike Intel API v2.0

Written by Slavik Markovich at Demisto
*/
package gocs

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	// DefaultURL is the URL for the API endpoint
	DefaultURL = "https://intelapi.crowdstrike.com/"
	// AuthHeaderID for the API
	AuthHeaderID = "X-CSIX-CUSTID"
	// AuthHeaderKey for the API
	AuthHeaderKey = "X-CSIX-CUSTKEY"
	// AllFields should be returned from the query
	AllFields = "__full__"
	// BasicFields should be returned from the query
	BasicFields = "__basic__"
)

// Intel interacts with the services provided by CrowdStrike Falcon Intelligence.
type Intel struct {
	*client
}

// NewIntel creates a new CS client.
//
// The caller can configure the new client by passing configuration options to the func.
//
// Example:
//
//   client, err := gocs.NewIntel(
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
func NewIntel(options ...OptionFunc) (*Intel, error) {
	options = append([]OptionFunc{SetURL(DefaultURL)}, options...)
	c, err := newClient(options...)
	if err != nil {
		return nil, err
	}
	return &Intel{client: c}, nil
}

// Structs

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
	Paging
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
	Parameter string     `json:"parameter"`
	Filter    string     `json:"filter"`
	Value     string     `json:"value"`
	Sort      *SortField `json:"sort"`
	Page      int        `json:"page"`
	PerPage   int        `json:"perPage"`
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
	Name             string  `json:"name"`
	CreatedOnEpoch   float64 `json:"created_on"`
	CreatedOn        time.Time
	LastValidOnEpoch float64 `json:"last_valid_on"`
	LastValidOn      time.Time
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
	Labels              []Label    `json:"labels"`
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

func (c *Intel) authFunc() func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set(AuthHeaderID, c.id)
		req.Header.Set(AuthHeaderKey, c.key)
	}
}

// Public API functions

// Actors will query the actors API
func (c *Intel) Actors(req *ActorRequest) (resp *ActorResponse, err error) {
	resp = &ActorResponse{}
	params := actorRequestToParams(req)
	err = c.do("GET", "actor/v1/queries/actors", params, nil, resp, c.authFunc())
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
	err = c.do("GET", "actor/v1/queries/actors", params, nil, w, c.authFunc())
	return
}

func indicatorRequestToParams(req *IndicatorRequest) url.Values {
	params := url.Values{req.Filter: {req.Value}}
	if req.Sort != nil {
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
	err = c.do("GET", "indicator/v1/search/"+req.Parameter, params, nil, &resp, c.authFunc())
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
	err = c.do("GET", "indicator/v1/search/"+req.Parameter, params, nil, w, c.authFunc())
	return
}
