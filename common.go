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

// Error structs are returned from this library for known error conditions
type Error struct {
	Code    string `json:"code"`    // Code of the error
	Message string `json:"message"` // Message of the error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

var (
	// ErrMissingCredentials is returned when API key is missing
	ErrMissingCredentials = &Error{Code: "missing_credentials", Message: "You must provide the CrowsStrike API ID and key"}
	// ErrMissingParams is returned if parameters are missing for a request
	ErrMissingParams = &Error{Code: "missing_parameters", Message: "You must provide the CrowsStrike API required parameters for the request"}
)

// client interacts with the services provided by CrowdStrike.
type client struct {
	id       string       // The API ID
	key      string       // The API key
	url      string       // CS URL
	errorlog *log.Logger  // Optional logger to write errors to
	tracelog *log.Logger  // Optional logger to write trace and debug data to
	c        *http.Client // The client to use for requests
}

// OptionFunc is a function that configures a Client.
// It is used in New
type OptionFunc func(*client) error

// errorf logs to the error log.
func (c *client) errorf(format string, args ...interface{}) {
	if c.errorlog != nil {
		c.errorlog.Printf(format, args...)
	}
}

// tracef logs to the trace log.
func (c *client) tracef(format string, args ...interface{}) {
	if c.tracelog != nil {
		c.tracelog.Printf(format, args...)
	}
}

func newClient(options ...OptionFunc) (*client, error) {
	// Set up the client
	c := &client{
		c: http.DefaultClient,
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
	return func(c *client) error {
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
	return func(c *client) error {
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
	return func(c *client) error {
		if rawurl == "" {
			rawurl = DefaultURL
		}
		u, err := url.Parse(rawurl)
		if err != nil {
			c.errorf("Invalid URL [%s] - %v\n", rawurl, err)
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			err := &Error{Code: "bad_url", Message: fmt.Sprintf("Invalid schema specified [%s]", rawurl)}
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
func SetErrorLog(logger *log.Logger) OptionFunc {
	return func(c *client) error {
		c.errorlog = logger
		return nil
	}
}

// SetTraceLog specifies the logger to use for output of trace messages like
// HTTP requests and responses. It is nil by default.
func SetTraceLog(logger *log.Logger) OptionFunc {
	return func(c *client) error {
		c.tracelog = logger
		return nil
	}
}

// dumpRequest dumps a request to the debug logger if it was defined
func (c *client) dumpRequest(req *http.Request) {
	if c.tracelog != nil {
		out, err := httputil.DumpRequestOut(req, false)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// dumpResponse dumps a response to the debug logger if it was defined
func (c *client) dumpResponse(resp *http.Response) {
	if c.tracelog != nil {
		out, err := httputil.DumpResponse(resp, true)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// Request handling functions

// handleError will handle responses with status code different from success
func (c *client) handleError(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if c.errorlog != nil {
			out, err := httputil.DumpResponse(resp, true)
			if err == nil {
				c.errorf("%s\n", string(out))
			}
		}
		msg := fmt.Sprintf("Unexpected status code: %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
		c.errorf(msg)
		return &Error{Code: "http_error", Message: msg}
	}
	return nil
}

// do executes the API request.
// Returns the response if the status code is between 200 and 299
// `body` is an optional body for the POST requests.
func (c *client) do(method, rawurl string, params url.Values, body io.Reader, result interface{}, authFunc func(*http.Request)) error {
	if len(params) > 0 {
		rawurl += "?" + params.Encode()
	}

	req, err := http.NewRequest(method, c.url+rawurl, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	authFunc(req)
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

// Common structs

// SortField ...
type SortField struct {
	Name      string `json:"name"`
	Ascending bool   `json:"ascending"`
}

// Paging control
type Paging struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
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
