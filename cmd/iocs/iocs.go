// Command line interface to CrowdStrike Intel API
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/demisto/gocs"
	"strings"
	"time"
)

var (
	id          string
	key         string
	types       string
	values      string
	policies    string
	shareLevels string
	sources     string
	from        string
	to          string
	limit       int
	offset      int
	sort        string
	asc         bool
	count       bool
	device      bool
	v           bool
)

func init() {
	flag.StringVar(&id, "i", os.Getenv("CS_ID"), "The id to use for CS API access. Can be provided as an environment variable CS_ID.")
	flag.StringVar(&key, "k", os.Getenv("CS_KEY"), "The key to use for CS API access. Can be provided as an environment variable CS_KEY.")
	flag.StringVar(&types, "types", "", "Types to filter on - sha256, sha1, md5, domain, ipv4, ipv6")
	flag.StringVar(&values, "values", "", "Values to filter on")
	flag.StringVar(&policies, "policies", "", "Policies to filter on - detect, none")
	flag.StringVar(&shareLevels, "shareLevels", "", "Share levels to filter on - red")
	flag.StringVar(&sources, "sources", "", "Sources levels to filter on")
	flag.StringVar(&from, "from", "", "From expiration timestamp in YYYY-MM-DD format to filter on")
	flag.StringVar(&to, "to", "", "To expiration timestamp in YYYY-MM-DD format to filter on")
	flag.IntVar(&limit, "limit", 100, "Number of results to retrieve")
	flag.IntVar(&offset, "offset", 0, "The page of results to retrieve")
	flag.StringVar(&sort, "sort", "", "Sort field - type, value, policy, share_level, expiration_timestamp")
	flag.BoolVar(&asc, "asc", false, "Sort in ascending order")
	flag.BoolVar(&count, "count", false, "If count is specified, do device count instead of search. You must specify types and values.")
	flag.BoolVar(&device, "device", false, "If device is specified, list devices instead of search. You must specify types and values.")
	flag.BoolVar(&v, "v", false, "Verbosity. If specified will trace the requests.")
}

func exit(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(code)
}

func check(e error) {
	if e != nil {
		exit(2, "Error - %v\n", e)
	}
}

func addStringList(s string, list *[]string) {
	l := strings.Split(s, ",")
	*list = append(*list, l...)
}

func parseTime(s string) *time.Time {
	if s != "" {
		t, err := time.Parse("2006-01-02", s)
		check(err)
		return &t
	}
	return nil
}

func main() {
	flag.Parse()
	initFuncs := []gocs.OptionFunc{gocs.SetErrorLog(log.New(os.Stderr, "", log.Lshortfile)), gocs.SetCredentials(id, key)}
	if v {
		initFuncs = append(initFuncs, gocs.SetTraceLog(log.New(os.Stderr, "", log.Lshortfile)))
	}
	cs, err := gocs.NewHost(initFuncs...)
	check(err)
	var b bytes.Buffer
	if count {
		check(cs.DeviceCountJSON(types, values, &b))
	} else if device {
		check(cs.DevicesRanOnJSON(types, values, &b))
	} else {
		req := &gocs.SearchIOCsRequest{}
		addStringList(types, &req.Types)
		addStringList(values, &req.Values)
		addStringList(policies, &req.Policies)
		addStringList(shareLevels, &req.ShareLevels)
		addStringList(sources, &req.Sources)
		req.FromExpirationTimestamp = parseTime(from)
		req.ToExpirationTimestamp = parseTime(to)
		if sort != "" {
			req.Sort = &gocs.SortField{Name: sort, Ascending: asc}
		}
		check(cs.SearchIOCsJSON(req, &b))
	}
	// Just for the indentation...
	m := make(map[string]interface{})
	check(json.Unmarshal(b.Bytes(), &m))
	data, err := json.MarshalIndent(m, "", "  ")
	check(err)
	fmt.Println(string(data))
}
