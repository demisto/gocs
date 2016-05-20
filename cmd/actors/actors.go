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
	"strings"
)

var (
	id         string
	key        string
	req        gocs.ActorRequest
	origin     string
	country    string
	industry   string
	motivation string
	jsonFormat bool
	v          bool
)

func init() {
	flag.StringVar(&id, "i", os.Getenv("CS_ID"), "The id to use for CS API access. Can be provided as an environment variable CS_ID.")
	flag.StringVar(&key, "k", os.Getenv("CS_KEY"), "The key to use for CS API access. Can be provided as an environment variable CS_KEY.")
	flag.StringVar(&req.Q, "q", "", "Search across all fields")
	flag.StringVar(&req.Name, "name", "", "Search based on name")
	flag.StringVar(&req.Description, "desc", "", "Search based on description")
	flag.StringVar(&origin, "origin", "", "Search based on origins")
	flag.StringVar(&country, "country", "", "Search based on target countries")
	flag.StringVar(&industry, "industry", "", "Search based on target industries")
	flag.StringVar(&motivation, "motive", "", "Search based on target motivations")
	flag.BoolVar(&jsonFormat, "json", false, "Should we print replies as JSON or formatted")
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

func main() {
	flag.Parse()
	cs, err := gocs.New(gocs.SetErrorLog(log.New(os.Stderr, "", log.Lshortfile)), gocs.SetCredentials(id, key))
	check(err)
	if v {
		gocs.SetTraceLog(log.New(os.Stderr, "", log.Lshortfile))(cs)
	}
	addStringList(origin, &req.Origins)
	addStringList(country, &req.TargetCountries)
	addStringList(industry, &req.TargetIndustries)
	addStringList(motivation, &req.Motivations)
	if jsonFormat {
		var b bytes.Buffer
		check(cs.ActorsJSON(&req, &b))
		// Just for the indentation...
		m := make(map[string]interface{})
		check(json.Unmarshal(b.Bytes(), &m))
		data, err := json.MarshalIndent(m, "", "  ")
		check(err)
		fmt.Println(string(data))
	} else {
		r, err := cs.Actors(&req)
		check(err)
		for i := range r.Resources {
			a := &r.Resources[i]
			fmt.Printf("%d\t%s\t%s\t%s\t%v\t%v\t%v\t%v\t%v\t%v\n",
				a.ID, a.Name, a.KnownAs, a.ShortDescription, a.Motivations, a.Origins, a.TargetCountries, a.TargetIndustries,
				a.FirstActivityDate, a.LastActivityDate)
		}
	}
}
