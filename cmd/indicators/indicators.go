// Command line interface to CrowdStrike Intel API
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"bytes"
	"encoding/json"
	"github.com/demisto/gocs"
)

var (
	id      string
	key     string
	param   string
	filter  string
	value   string
	page    int
	perPage int
	sort    string
	asc     bool
	v       bool
)

func init() {
	flag.StringVar(&id, "i", os.Getenv("CS_ID"), "The id to use for CS API access. Can be provided as an environment variable CS_ID.")
	flag.StringVar(&key, "k", os.Getenv("CS_KEY"), "The key to use for CS API access. Can be provided as an environment variable CS_KEY.")
	flag.StringVar(&param, "param", "", "The indicator parameter to search")
	flag.StringVar(&filter, "filter", "", "The filter for the search")
	flag.StringVar(&value, "value", "", "The filter value for the search")
	flag.IntVar(&page, "page", 1, "The requested page - 1 based")
	flag.IntVar(&perPage, "pagesize", 10, "How many indicators to retrieve per page")
	flag.StringVar(&sort, "sort", "", "Sort field")
	flag.BoolVar(&asc, "asc", false, "Sort in ascending order")
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

func main() {
	flag.Parse()
	cs, err := gocs.New(gocs.SetErrorLog(log.New(os.Stderr, "", log.Lshortfile)), gocs.SetCredentials(id, key))
	check(err)
	if v {
		gocs.SetTraceLog(log.New(os.Stderr, "", log.Lshortfile))(cs)
	}
	var b bytes.Buffer
	req := &gocs.IndicatorRequest{Parameter: param, Filter: filter, Value: value, Page: page, PerPage: perPage}
	if sort != "" {
		req.Sort.Name = sort
		req.Sort.Ascending = asc
	}
	check(cs.IndicatorsJSON(req, &b))
	// Just for the indentation...
	m := []interface{}{}
	check(json.Unmarshal(b.Bytes(), &m))
	data, err := json.MarshalIndent(m, "", "  ")
	check(err)
	fmt.Println(string(data))
}
