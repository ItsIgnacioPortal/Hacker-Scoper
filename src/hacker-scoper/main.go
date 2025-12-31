package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

const firebountyAPIURL = "https://firebounty.com/api/v1/scope/all/url_only/"
const firebountyJSONFilename = "firebounty-scope-url_only.json"

var firebountyJSONPath string

var ErrInvalidFormat = errors.New("invalid format: not IP, CIDR, or URL")

type URLWithIPAddressHost struct {
	rawURL string
	IPhost net.IP
}

type WildcardScope struct {
	scope regexp.Regexp
}

type NmapIPRange struct {
	Octets [4][]uint8 // Each octet can be a list of allowed values
	Raw    string     // Original string for reference
}

// https://tutorialedge.net/golang/parsing-json-with-golang/
type Scope struct {
	Scope      string //either a domain, or a wildcard domain
	Scope_type string //we only care about "web_application"
}

type Program struct {
	Firebounty_url string //url.URL not allowed appearently
	Scopes         struct {
		In_scopes     []Scope
		Out_of_scopes []Scope
	}
	Slug string
	Tag  string
	Url  string //url.URL not allowed appearently
	Name string
}

type firebountySearchMatch struct {
	companyIndex int
	companyName  string
}

// Define a minimal struct for just the company names
type PartialProgram struct {
	Name string `json:"name"`
}

type PartialFirebounty struct {
	Pgms []PartialProgram `json:"pgms"`
}

type parseResult struct {
	value interface{}
	line  string
	err   error
}

type targetResult struct {
	index         int
	parsedTarget  interface{}
	err           error
	isInsideScope bool
	isUnsure      bool
	targetStr     string
}

var chainMode bool

const colorReset = "\033[0m"
const colorYellow = "\033[33m"
const colorRed = "\033[38;2;255;0;0m"
const colorGreen = "\033[38;2;37;255;36m"
const colorBlue = "\033[38;2;0;204;255m"

func main() {

	StartBenchmark("1")

	var targetsListFilepath string
	var includeUnsure bool
	var inscopeOutputFile string
	var outputDomainsOnly bool

	var quietMode bool
	var showVersion bool
	var company string
	var inscopeExplicitLevel int //should only be [0], 1, or 2
	var noscopeExplicitLevel int //should only be [0], 1, or 2
	var scopesListFilepath string
	var outofScopesListFilepath string
	var privateTLDsAreEnabled bool

	const usage = `Hacker-scoper is a GoLang tool designed to assist cybersecurity professionals in bug bounty programs. It identifies and excludes URLs and IP addresses that fall outside a program's scope by comparing input targets (URLs/IPs) against a locally cached [FireBounty](https://firebounty.com) database of scraped scope data. Users may also supply a custom scope list for validation.

` + colorBlue + `Usage:` + colorReset + ` hacker-scoper --file /path/to/targets [--company company | --inscopes-file /path/to/inscopes [--outofscopes-file /path/to/outofscopes] [--enable-private-tlds]] [--inscope-explicit-level INT] [--noscope-explicit-level INT] [--chain-mode] [--database /path/to/firebounty.json] [--include-unsure] [--output /path/to/outputfile] [--hostnames-only]

` + colorBlue + `Usage examples:` + colorReset + `
  Example: Cat a file, and lookup scopes on firebounty
  ` + colorGreen + `cat recon-targets.txt | hacker-scoper -c google` + colorReset + `

  Example: Cat a file, and use the .inscope & .noscope files
  ` + colorGreen + `cat recon-targets.txt | hacker-scoper` + colorReset + `

  Example: Manually pick a file, lookup scopes on firebounty, and set inscope explicit-level
  ` + colorGreen + `hacker-scoper -f recon-targets.txt -c google -ie 2` + colorReset + `

  Example: Manually pick a file, use custom scopes and out-of-scope files, and set inscope explicit-level
  ` + colorGreen + `hacker-scoper -f recon-targets.txt -ins inscope -oos noscope.txt -ie 2 ` + colorReset + `

` + colorBlue + `Usage notes:` + colorReset + `
  If no company and no inscope file is specified, hacker-scoper will look for ".inscope" and ".noscope" files in the current or in parent directories.

` + colorBlue + `List of all possible arguments:` + colorReset + `
  -c, --company string
      Specify the company name to lookup.

  -f, --file string
      Path to your file containing URLs

  -ins, --inscope, --in-scope, --in-scope-file, --inscope-file string
      Path to a custom plaintext file containing scopes

  -oos, --outofscope, --out-of-scope, --out-of-scope-file, --outofscope-file string
      Path to a custom plaintext file containing scopes exclusions

  -ie, --inscope-explicit-level int
  -oe, --noscope-explicit-level int
      How explicit we expect the scopes to be:
        (default) 1: Include subdomains in the scope even if there's not a wildcard in the scope.
                  2: Include subdomains in the scope only if there's a wildcard in the scope.
                  3: Include subdomains/IPs in the scope only if they are explicitly within the scope. CIDR ranges and wildcards are disabled.

  --enable-private-tlds
      Set this flag to enable the use of company scope domains with private TLDs. This essentially disables the bug-bounty-program misconfiguration detection.

  -ch, --chain-mode, --plain, --raw, --no-ansi
      In "chain-mode" we only output the important information. No decorations.
	    Default: false

  --database string
      Custom path to the cached firebounty database.
	  	Default:
		- Windows: %APPDATA%\hacker-scoper\
		- Linux: /etc/hacker-scoper/

  -iu, --include-unsure
      Include "unsure" assets in the output. An unsure asset is an asset that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.

  -o, --output string
      Save the inscope assets to a file

  --quiet
      Disable command-line output.

  -ho, --hostnames-only
      When handling URLs, output only their hostnames instead of the full URLs

  --version
      Show the installed version

`

	flag.StringVar(&company, "c", "", "Specify the company name to lookup.")
	flag.StringVar(&company, "company", "", "Specify the company name to lookup.")
	flag.StringVar(&targetsListFilepath, "f", "", "Path to your file containing URLs")
	flag.StringVar(&targetsListFilepath, "file", "", "Path to your file containing URLs")
	flag.StringVar(&scopesListFilepath, "ins", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&scopesListFilepath, "inscope", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&scopesListFilepath, "in-scope", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&scopesListFilepath, "in-scope-file", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&scopesListFilepath, "inscope-file", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&outofScopesListFilepath, "oos", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.StringVar(&outofScopesListFilepath, "outofscope", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.StringVar(&outofScopesListFilepath, "out-of-scope", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.StringVar(&outofScopesListFilepath, "outofscope-file", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.StringVar(&outofScopesListFilepath, "out-of-scope-file", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.IntVar(&inscopeExplicitLevel, "ie", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&inscopeExplicitLevel, "inscope-explicit-level", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&inscopeExplicitLevel, "in-scope-explicit-level", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&noscopeExplicitLevel, "oe", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&noscopeExplicitLevel, "noscope-explicit-level", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&noscopeExplicitLevel, "no-scope-explicit-level", 1, "Level of explicity expected. ([1]/2/3)")
	flag.BoolVar(&privateTLDsAreEnabled, "enable-private-tlds", false, "Set this flag to enable the use of company scope domains with private TLDs. This essentially disables the bug-bounty-program misconfiguration detection.")
	flag.BoolVar(&chainMode, "ch", false, "Output only the important information. No decorations.")
	flag.BoolVar(&chainMode, "chain-mode", false, "Output only the important information. No decorations.")
	flag.BoolVar(&chainMode, "plain", false, "Output only the important information. No decorations.")
	flag.BoolVar(&chainMode, "raw", false, "Output only the important information. No decorations.")
	flag.BoolVar(&chainMode, "no-ansi", false, "Output only the important information. No decorations.")
	flag.StringVar(&firebountyJSONPath, "database", "", "Custom path to the cached firebounty database")
	flag.StringVar(&inscopeOutputFile, "o", "", "Save the inscope urls to a file")
	flag.StringVar(&inscopeOutputFile, "output", "", "Save the inscope urls to a file")
	flag.BoolVar(&quietMode, "quiet", false, "Disable command-line output.")
	flag.BoolVar(&showVersion, "version", false, "Show installed version")
	flag.BoolVar(&includeUnsure, "iu", false, "Include \"unsure\" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.")
	flag.BoolVar(&includeUnsure, "include-unsure", false, "Include \"unsure\" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.")
	flag.BoolVar(&outputDomainsOnly, "ho", false, "Output only domains instead of the full URLs")
	flag.BoolVar(&outputDomainsOnly, "hostnames-only", false, "Output only domains instead of the full URLs")
	//https://www.antoniojgutierrez.com/posts/2021-05-14-short-and-long-options-in-go-flags-pkg/
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	banner := `
'||                      '||                      '
 || ..    ....     ....   ||  ..    ....  ... ..     ....    ....    ...   ... ...    ....  ... ..
 ||' ||  '' .||  .|   ''  || .'   .|...||  ||' ''   ||. '  .|   '' .|  '|.  ||'  || .|...||  ||' ''
 ||  ||  .|' ||  ||       ||'|.   ||       ||       . '|.. ||      ||   ||  ||    | ||       ||
.||. ||. '|..'|'  '|...' .||. ||.  '|...' .||.      |'..|'  '|...'  '|..|'  ||...'   '|...' .||.
                                                                            ||
                                                                           ''''
`

	if showVersion {
		fmt.Print("hacker-scoper: v6.1.4\n")
		os.Exit(0)
	}

	if quietMode && inscopeOutputFile == "" {
		warning("--quiet was set, but no output file was specified. Program will do nothing.")
		os.Exit(2)
	}

	// This avoids having to check both chainMode and quietMode in the future. Instead we can just check chainMode.
	if quietMode && !chainMode {
		chainMode = quietMode
	}

	if firebountyJSONPath == "" {
		firebountyJSONPath = getFirebountyJSONPath()
		if firebountyJSONPath == "" && !chainMode {
			warning("This OS isn't officially supported. The firebounty JSON will be downloaded in the current working directory. To override this behaviour, use the \"--database\" flag.")
		}
	} else {
		//If the folder exists...
		_, err := os.Stat(firebountyJSONPath)
		if errors.Is(err, os.ErrNotExist) {
			//Create the folder
			err := os.Mkdir(firebountyJSONPath, 0600)
			if err != nil {
				crash("Unable to create the folder \""+firebountyJSONPath+"\"", err)
			}
		} else if err != nil {
			// Schrodinger: file may or may not exist. See err for details.
			crash("Could not verify existance of the folder \""+firebountyJSONPath+"\"!", err)
		}
	}

	firebountyJSONPath = firebountyJSONPath + firebountyJSONFilename

	if !chainMode {
		fmt.Println(banner)
	}

	//validate arguments
	if inscopeExplicitLevel != 1 && inscopeExplicitLevel != 2 && inscopeExplicitLevel != 3 {
		var err error
		crash("Invalid in-scope explicit-level selected", err)
	}
	if noscopeExplicitLevel != 1 && noscopeExplicitLevel != 2 && noscopeExplicitLevel != 3 {
		var err error
		crash("Invalid no-scope explicit-level selected", err)
	}

	// Validate the targets input
	var targetsInput []string

	// If we're getting input from stdin...
	//https://stackoverflow.com/a/26567513/11490425
	stat, _ := os.Stdin.Stat()
	if (stat.Mode()&os.ModeCharDevice) == 0 && !isVSCodeDebug() {

		// Read all of stdin into targetsInput

		//read stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
				targetsInput = append(targetsInput, line)
			}
		}
		if err := scanner.Err(); err != nil {
			crash("bufio couldn't read stdin correctly.", err)
		}

	} else if targetsListFilepath != "" {
		// We didn't get anything from stdin, so we will use the file specified by the user
		// Immediatly open the file specified by the user to prevent the file from potentially being modified by another process, exploiting a race condition (CWE-377)

		// Load the user-supplied targets file into memory
		var err error
		targetsInput, err = readFileLines(targetsListFilepath)
		if err != nil {
			crash("Could not read the file "+targetsListFilepath, err)
		}

	} else {
		// We didn't get anything from stdin, and the user didn't specify a file
		// Print a usage warning, then quit gracefully

		if !chainMode {
			fmt.Println(string(colorRed) + "[-] No input file specified. Please specify a file with the -f or --file argument." + string(colorReset))
			fmt.Println(string(colorRed) + "[-] Run with \"--help\" for more information." + string(colorReset))
		}

		// Exit code 2 = command line syntax error
		os.Exit(2)
	}

	var inscopeLines []string
	var noscopeLines []string

	// Validate the inscope input
	if company == "" && scopesListFilepath == "" {
		// If the user didn't specify a company name, and also didn't specify a filepath for the inscope and outofscope files, we'll search for .inscope and .noscope files.

		if !chainMode {
			fmt.Print("No company or scopes file specified. Looking for \".inscope\" and \".noscope\" files..." + "\n")
		}

		//look for .inscope file
		inscopePath, err := searchForFileBackwards(".inscope")
		if err != nil {
			crash("Couldn't locate a .inscope file.", err)
		}

		if !chainMode {
			fmt.Print(".inscope found. Using " + inscopePath + "\n")
		}

		//look for .noscope file
		noscopePath, err := searchForFileBackwards(".noscope")
		if err != nil {
			noscopePath = ""
		} else if !chainMode {
			fmt.Print(".noscope found. Using " + noscopePath + "\n")
		}

		// Load the inscope file into memory
		inscopeLines, err = readFileLines(inscopePath)
		if err != nil {
			crash(".inscope file found at "+inscopePath+" but couldn't be read.", err)
		}

		// Load the noscope file into memory
		noscopeLines, err = readFileLines(noscopePath)
		if err != nil {
			crash(".noscope file found at "+noscopePath+" but couldn't be read.", err)
		}

	} else if company != "" {
		// If the user inputted a company name, we'll lookup said company in the firebounty db

		// If the db exists...
		if firebountyJSONFileStats, err := os.Stat(firebountyJSONPath); err == nil {
			//check age. if age > 24hs
			yesterday := time.Now().Add(-24 * time.Hour)
			if firebountyJSONFileStats.ModTime().Before(yesterday) {
				if !chainMode {
					fmt.Println("[INFO]: +24hs have passed since the last update to the local firebounty database. Updating...")
				}
				updateFireBountyJSON()
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// The database does not exist.
			// We'll create it.
			if !chainMode {
				fmt.Println("[INFO]: Downloading scopes file and saving in \"" + firebountyJSONPath + "\"")
			}
			updateFireBountyJSON()
		} else {
			crash("Unable to get information about the database file at \""+firebountyJSONPath+"\". Probably a permissions error with the directory the database is saved at. Try using the database argument like '--database /custom/path/to/store/the/firebounty.json'", err)
		}

		// Get the company names from the JSON file
		companyNames, err := extractCompanyNames(firebountyJSONPath)
		if err != nil {
			crash("Couldn't parse company names from firebounty JSON.", err)
		}

		var matchingCompanyList []firebountySearchMatch
		var userChoice string
		var userPickedInvalidChoice bool = true
		var userChoiceAsInt int

		//for every company...
		for i, fcompany := range companyNames {
			fcompany := strings.ToLower(fcompany)
			if strings.Contains(fcompany, company) {
				matchingCompanyList = append(matchingCompanyList, firebountySearchMatch{i, fcompany})
			}
		}
		if len(matchingCompanyList) == 0 && !chainMode {
			fmt.Println(string(colorRed) + "[-] 0 (lowercase'd) company names contained the string \"" + company + "\"" + string(colorReset))
			fmt.Println(string(colorRed) + "[-] If the company's bug bounty program is private, consider using rescope to download the scopes: https://github.com/root4loot/rescope")
			fmt.Println(string(colorRed) + "[-] If the company's bug bounty program is public, consider either of these options:")
			fmt.Println(string(colorRed) + "\t - Doing a manual search at https://firebounty.com")
			fmt.Println(string(colorRed) + "\t - Loading the scopes manually into '.inscope' and '.noscope' files.")
			fmt.Println(string(colorRed) + "\t - Loading the scopes manually into custom files, specified with the --inscope-file and --outofscope-file arguments.")
			// Exit code 2 = command line syntax error
			os.Exit(2)
		} else if len(matchingCompanyList) > 1 {

			if chainMode {
				err = nil
				crash("Unable to match the company to a single company. Please use a more exact company string.", err)
			}

			//appearently "while" doesn't exist in Go. It has been replaced by "for"
			for userPickedInvalidChoice {
				//For every matchingCompanyList item...
				for i := range matchingCompanyList {
					//Print it
					fmt.Println("    " + strconv.Itoa(i) + " - " + matchingCompanyList[i].companyName)
				}

				//Show user the option to combine all of the previous companies as if they were a single company
				fmt.Println("    " + strconv.Itoa(len(matchingCompanyList)) + " - COMBINE ALL")

				//Get userchoice
				fmt.Print("\n[+] Multiple companies matched \"" + company + "\". Please choose one: ")
				_, err = fmt.Scanln(&userChoice)
				if err != nil {
					crash("An error ocurred while reading user input.", err)
				}

				//Convert userchoice str -> int
				userChoiceAsInt, err = strconv.Atoi(userChoice)
				//If the user picked something invalid...
				if err != nil {
					warning("Invalid option selected!")
				} else {
					userPickedInvalidChoice = false
				}
			}

			//tip
			fmt.Println("[-] If you want to remove one of these options, feel free to modify your firebounty database: " + firebountyJSONPath + "\n")

			//If the user chose to "COMBINE ALL"...
			if userChoiceAsInt == len(matchingCompanyList) {
				//for every company that matched the company query...
				for i := range matchingCompanyList {

					//Load the matchingCompanyList 2D slice, and convert the first member from string to integer, and save the company index
					companyIndex := matchingCompanyList[i].companyIndex
					tempinscopeLines, tempnoscopeLines, err := getCompanyScopes(firebountyJSONPath, &companyIndex, privateTLDsAreEnabled)
					if err != nil {
						crash("Error parsing the company "+company, err)
					}

					inscopeLines = append(inscopeLines, tempinscopeLines...)
					noscopeLines = append(noscopeLines, tempnoscopeLines...)

				}
			} else {
				// The user chose a specific company
				// Use userChoiceAsInt as an index for the matchingCompanyList 2D slice, and save the company index
				companyCounter := matchingCompanyList[userChoiceAsInt].companyIndex
				inscopeLines, noscopeLines, err = getCompanyScopes(firebountyJSONPath, &companyCounter, privateTLDsAreEnabled)
				if err != nil {
					crash("Error parsing the company "+company, err)
				}
			}

		} else {
			//Only 1 company matched the query
			if !chainMode {
				fmt.Print("[+] Search for \"" + company + "\" matched the company " + string(colorGreen) + matchingCompanyList[0].companyName + string(colorReset) + "!\n")
			}
			inscopeLines, noscopeLines, err = getCompanyScopes(firebountyJSONPath, &matchingCompanyList[0].companyIndex, privateTLDsAreEnabled)
			if err != nil {
				crash("Error parsing the company "+company, err)
			}
		}

	} else {
		//user chose to use their own scope list
		if _, err := os.Stat(scopesListFilepath); err == nil {
			// path/to/whatever exists

			// Load the user-supplied inscopes file into memory
			inscopeLines, err = readFileLines(scopesListFilepath)
			if err != nil {
				crash("Error reading the file "+scopesListFilepath, err)
			}

			// The outofScopesListFilepath might, or might not have been specified.
			// If a custom outofScopesListFilepath was specified...
			if outofScopesListFilepath != "" {
				// Load the user-supplied noscopes file into memory
				noscopeLines, err = readFileLines(outofScopesListFilepath)
				if err != nil {
					crash("Error reading the file "+outofScopesListFilepath, err)
				}
			}

		} else if errors.Is(err, os.ErrNotExist) {
			//path/to/whatever does not exist
			err = nil
			crash(scopesListFilepath+" does not exist.", err)

		} else {
			// Schrodinger: file may or may not exist. See err for details.
			panic(err)
		}
	}

	StopBenchmark()
	StartBenchmark("2")

	// Parse all inscopeLines lines
	inscopeScopes, err := parseAllLines(inscopeLines, true)
	if err != nil {
		crash("Unable to parse any inscope entries as scopes", err)
	}

	// Parse all noscopeLines lines
	noscopeScopes, err := parseAllLines(noscopeLines, true)
	if err != nil {
		warning("Unable to parse any noscope entries as scopes")
	}

	// Variables for writing the output to a file if necessary.
	var writer *bufio.Writer
	var f *os.File

	if inscopeOutputFile != "" {
		f, err := os.OpenFile(inscopeOutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600) // #nosec G304 -- inscopeOutputFile is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
		if err != nil {
			crash("Unable to read output file", err)
		}

		// Use bufio.Writer for efficient disk writes
		writer = bufio.NewWriter(f)
	}

	// Parse all targetsInput lines concurrently
	numWorkers := runtime.NumCPU()
	inputChan := make(chan int, numWorkers)
	outputChan := make(chan targetResult, len(targetsInput))

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range inputChan {
				parsedTarget, err := parseLine(targetsInput[idx], false)
				res := targetResult{
					index:        idx,
					parsedTarget: parsedTarget,
					err:          err,
					targetStr:    targetsInput[idx],
				}
				if err == nil {
					isInsideScope, isUnsure := parseScopes(&inscopeScopes, &noscopeScopes, &parsedTarget, &inscopeExplicitLevel, &noscopeExplicitLevel, includeUnsure)
					res.isInsideScope = isInsideScope
					res.isUnsure = isUnsure
				}
				outputChan <- res
			}
		}()
	}

	// Feed indices to workers
	go func() {
		for i := range targetsInput {
			inputChan <- i
		}
		close(inputChan)
	}()

	go func() {
		wg.Wait()
		close(outputChan)
	}()

	// Variables for writing the output to a file if necessary.
	var target string
	results := make([]targetResult, len(targetsInput))
	for res := range outputChan {
		results[res.index] = res
	}

	// Output results in original order
	for _, res := range results {
		if res.err != nil {
			warning("Unable to parse the string '" + res.targetStr + "' as a target.")
			continue
		}
		if res.isInsideScope {
			if outputDomainsOnly {
				switch assertedTarget := res.parsedTarget.(type) {
				case *url.URL:
					target = removePortFromHost(assertedTarget)
				case *URLWithIPAddressHost:
					target = assertedTarget.IPhost.String()
				default:
					target = res.targetStr
				}
			} else {
				target = res.targetStr
			}
			if !quietMode {
				if res.isUnsure && includeUnsure {
					if !chainMode {
						infoWarning("UNSURE: ", target)
					} else {
						fmt.Println(target)
					}
				} else {
					if !chainMode {
						infoGood("IN-SCOPE: ", target)
					} else {
						fmt.Println(target)
					}
				}
			}
			if inscopeOutputFile != "" {
				_, err = writer.WriteString(target + "\n")
				if err != nil {
					crash("Unable to write to output file", err)
				}
			}
		}
	}
	// ...existing code...

	if inscopeOutputFile != "" {
		// Flush any buffered data to disk
		writer.Flush() // #nosec G104 -- No need to handle any writer errors, since we already crash upon encountering any writer error.

		//Close the output file
		f.Close() // #nosec G104 -- There's no harm done if we're unable to close the output file, since we're already at the end of the program.
	}

	StopBenchmark()

}

func updateFireBountyJSON() {
	// path/to/whatever does *not* exist
	//get the big JSON from the API
	jason, err := http.Get(firebountyAPIURL)
	if err != nil {
		crash("Could not download scopes from firebounty at: "+firebountyAPIURL, err)
	}

	//read the contents of the request
	body, err := io.ReadAll(jason.Body)
	jason.Body.Close() // #nosec G104 -- There is no situation in which closing the body of the request will cause an error.
	if err != nil {
		fmt.Println(err)
	}

	//delete the previous file (if it even exists)
	os.Remove(firebountyJSONPath) // #nosec G104 -- There is no need to handle any errors in deleting the file, as it will be created again in the next step.

	//write to disk
	err = os.WriteFile(firebountyJSONPath, []byte(string(body)), 0600)
	if err != nil {
		crash("Couldn't save firebounty json to disk as"+firebountyJSONPath, err)
	}

	if !chainMode {
		fmt.Println("[INFO]: Scopes file saved to " + firebountyJSONPath)
	}

}

func parseScopes(inscopeScopes *[]interface{}, noscopeScopes *[]interface{}, target *interface{}, inscopeExplicitLevel *int, noscopeExplicitLevel *int, includeUnsure bool) (isInsideScope bool, isUnsure bool) {
	// This function is where we'll implement the --include-unsure logic

	targetIsOutOfScope := isOutOfScope(noscopeScopes, target, noscopeExplicitLevel)
	if !targetIsOutOfScope {
		// We only need to check if the target is inscope if it isn't out of scope.
		targetIsInscope := isInscope(inscopeScopes, target, inscopeExplicitLevel)
		if targetIsInscope {
			return true, false
		} else if includeUnsure && !targetIsInscope {
			return true, true
		} else {
			return false, false
		}
	} else {
		return false, false
	}
}

func crash(message string, err error) {
	fmt.Fprintf(os.Stderr, string(colorRed)+"[ERROR]: "+message+string(colorReset)+"\n\n")
	fmt.Fprintf(os.Stderr, string(colorRed)+"Error stacktrace: "+string(colorReset)+"\n")
	panic(err)
}

func warning(message string) {
	fmt.Fprintf(os.Stderr, string(colorYellow)+"[WARNING]: "+message+string(colorReset)+"\n")
}

func infoGood(prefix string, message string) {
	fmt.Print(string(colorGreen) + "[+] " + prefix + string(colorReset) + message + "\n")
}

func infoWarning(prefix string, message string) {
	fmt.Print(string(colorYellow) + "[-] " + prefix + string(colorReset) + message + "\n")
}

func removePortFromHost(myurl *url.URL) string {
	portLength := len(myurl.Port())
	if portLength != 0 {
		hostLength := len(myurl.Host)
		// The last "-1" removes the ":" character from the host.
		portless := myurl.Host[:hostLength-portLength-1]
		return portless
	} else {
		return myurl.Host
	}
}

// out-of-scopes are parsed as --explicit-level==2
func isOutOfScope(noscopeScopes *[]interface{}, target *interface{}, explicitLevel *int) bool {
	//if we got no matches for any outOfScope
	return isInscope(noscopeScopes, target, explicitLevel)
}

//======================================================================================
// The following code is from tomnomnom's inscope project:
// https://github.com/tomnomnom/hacks/tree/master/inscope

func searchForFileBackwards(filename string) (string, error) {
	pwd, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}

	for {
		_, err := os.Stat(filepath.Join(pwd, filename))

		// found one!
		if err == nil {
			return filepath.Join(pwd, filename), nil
		}

		newPwd := filepath.Dir(pwd)
		if newPwd == pwd {
			break
		}
		pwd = newPwd
	}

	return "", errors.New("unable to locate a \".scope\" file")
}

//======================================================================================

// companyIndex is the numeric index of the company in the firebounty database, where 0 is the first company, 1 is the second company, etc
// Returns an error if no inscopeLines could be detected.
// Does not return an error if no noscopeLines could be detected.
func getCompanyScopes(firebountyJSONPath string, companyIndex *int, privateTLDsAreEnabled bool) (inscopeLines []string, noscopeLines []string, err error) {

	prog, err := loadProgramByIndex(firebountyJSONPath, *companyIndex)
	if err != nil {
		crash("Couldn't load full program data", err)
	}

	//match found!
	if !chainMode {

		// Print the details of the matched company in a readable format

		// Get the last date the cached database was updated
		info, err := os.Stat(firebountyJSONPath)
		if err != nil {
			crash("Error getting file information for the database file at "+firebountyJSONFilename, err)
		}
		// info.Atime_ns now contains the last access time
		// (in nanoseconds since the unix epoch)
		// Convert the date to the format YYYY-MM-DD HH:MM
		lastUpdated := time.Unix(info.ModTime().Unix(), 0).Format("2006-01-02 15:04:05")
		fmt.Println("[+] Last updated: " + lastUpdated)

		// Print the details of the matched company in a readable format
		fmt.Println("[+] Firebounty URL: " + prog.Firebounty_url)
		fmt.Println("[+] Program URL: " + prog.Url)

		// Print the in-scope rules
		fmt.Println("[+] In-scope rules: ")
		for _, inscope := range prog.Scopes.In_scopes {
			fmt.Println("\t[+] " + inscope.Scope_type + ": " + inscope.Scope)
		}

		// Print the out-of-scope rules
		fmt.Println("\n[+] Out-of-scope rules: ")
		for _, noscope := range prog.Scopes.Out_of_scopes {
			fmt.Println("\t[+] " + noscope.Scope_type + ": " + noscope.Scope)
		}

		fmt.Println("\n[+] Analysis started...")

	}

	//for every InScope Scope in the program
	for inscopeCounter := 0; inscopeCounter < len(prog.Scopes.In_scopes); inscopeCounter++ {
		//if the scope type is "web_application" and it's not empty
		if prog.Scopes.In_scopes[inscopeCounter].Scope_type == "web_application" && prog.Scopes.In_scopes[inscopeCounter].Scope != "" {

			rawInScope := prog.Scopes.In_scopes[inscopeCounter].Scope

			// TODO: Optimize this. It's very inneficient to be parsing this line twice. parseLine is already called within isAndroidPackageName, so we shouldn't call it again, that's redundant.
			if !isAndroidPackageName(&rawInScope, privateTLDsAreEnabled) {
				inscopeLines = append(inscopeLines, rawInScope)
			}

		}
	}

	if len(inscopeLines) == 0 {
		return nil, nil, errors.New("Unable to parse any inscopes scopes from " + prog.Name)
	}

	//for every NoScope Scope in the program
	for noscopeCounter := 0; noscopeCounter < len(prog.Scopes.Out_of_scopes); noscopeCounter++ {
		//if the scope type is "web_application" and it's not empty
		if prog.Scopes.Out_of_scopes[noscopeCounter].Scope_type == "web_application" && prog.Scopes.Out_of_scopes[noscopeCounter].Scope != "" {

			rawNoScope := prog.Scopes.Out_of_scopes[noscopeCounter].Scope

			if !isAndroidPackageName(&rawNoScope, privateTLDsAreEnabled) {
				noscopeLines = append(noscopeLines, rawNoScope)
			}

		}
	}

	return inscopeLines, noscopeLines, nil
}

// This function receives a raw scope string, and returns true if it's an android package name.
// It's goal is to help detect any misconfigured bug-bounty programs
// Only scopes that have the type "web_application" but that we aren't sure if they are actually web_application resources should be sent into this function.
// Sometimes bug bounty programs set APK package names such as com.my.businness.gatewayportal as web_application resources instead of as android_application resources in their program scope, causing trouble for anyone using automatic tools. Hacker-Scoper automatically detects these errors and notifies the user.
func isAndroidPackageName(rawScope *string, privateTLDsAreEnabled bool) bool {

	if privateTLDsAreEnabled {
		return privateTLDsAreEnabled
	}

	// We begin the detection by trying to parse the given scope as an actual scope.
	// The problem with url.Parse is that it rarely returns an error. It often times assumes that invalid domain names (such as "this.is.not.avaliddomain") actually have a "private Top-Level-Domain". This is extremely unlikely in reality
	// TODO: Split parseLine into 3 functions, so we can directly try to parse the rawScope as a URL rather than wasting CPU cycles trying to parse CIDR Range -> IP Address -> URL.
	inscope, err := parseLine(*rawScope, true)

	if err != nil {
		return false
	} else if _, inscopeIsURL := inscope.(*url.URL); inscopeIsURL {
		// If the type of inscope is *url.URL ...
		portlessHostofCurrentTarget := removePortFromHost(inscope.(*url.URL))

		//alert the user about potentially mis-configured bug-bounty program
		_, scopeHasValidTLD := publicsuffix.PublicSuffix(portlessHostofCurrentTarget)

		if !chainMode {
			//alert the user about potentially mis-configured bug-bounty program
			if (*rawScope)[0:4] == "com." || (*rawScope)[0:4] == "org." {
				warning("The scope \"" + *rawScope + "\" starts with \"com.\" or \"org.\" This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the maintainers of the bug bounty program.")
			}
		}

		if !scopeHasValidTLD && inscope.(*url.URL).Host != "" {
			if !chainMode {
				warning("The scope \"" + *rawScope + "\" does not have a public Top Level Domain (TLD). This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the mainters of the bug bounty program.")
			}
			return true
		}
	}

	return false
}

// This function receives a filepath as a string, and returns a string with the contents of the file
// All lines are trimmed, and empty lines are removed
// All lines beginning with '#' or '//' are considered comments and are removed
func readFileLines(filepath string) ([]string, error) {
	// Reads the whole file into memory
	data, err := os.ReadFile(filepath) // #nosec G304 -- Intended functionality.
	if err != nil {
		return nil, err
	}
	rawLines := strings.Split(string(data), "\n")
	var lines []string
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// If isScope is true, ParseLine attempts to parse a string into either:
// - *net.IPNet		(CIDR notation)
// - *net.IP		(single IP address)
// - *string 		(hostname of a valid URL)
// - *regexp.Regexp (Regex)
// - *WildcardScope (Wildcard Scope)
//
// If isScope is false, ParseLine attempts to parse a string into either:
// - *net.IP				(single IP address)
// - *url.URL				(valid URL)
// - *URLWithIPAddressHost	(URL that has an IP host)
//
// This function returns the error ErrInvalidFormat if the string didn't match any of the listed formats.
func parseLine(line string, isScope bool) (interface{}, error) {

	// TODO: Add a --optimize flag that when enabled will save all of the inscope, and noscope scopes in a separate file, with their type already determined, so we don't have to waste time guessing the scope type every time hacker-scoper is run. Maybe in CSV format. We could also use the file last-modified-at metadata to know whether the .inscope and .noscope files were modified. The --optimize flag should only have an effect when hacker-scoper is ran with .inscope and .noscope files, or with the firebounty db.It wouldn't make sense to optimize the input of stdin.

	if isScope {
		if strings.HasPrefix(line, "^") && strings.HasSuffix(line, "$") {
			// Attempt to parse the scope as a regex
			scopeRegex, err := regexp.Compile(line)
			if err != nil {
				if chainMode {
					warning("There was an error parsing the scope \"" + line + "\" as a regex.")
				}
				return nil, ErrInvalidFormat
			} else {
				return scopeRegex, nil
			}
		} else if strings.Contains(line, "*") {
			// If the line is a scope and contains a wildcard...
			// Attempt to parse the scope as a regex
			rawRegex := strings.Replace(line, ".", "\\.", -1)
			rawRegex = strings.Replace(rawRegex, "*", ".*", -1)

			scopeRegex, err := regexp.Compile(rawRegex)
			if err != nil {
				if chainMode {
					warning("There was an error parsing the scope \"" + line + "\" (converted into \"" + rawRegex + "\") as a regex. This scope was parsed as a regex instead of as a URL because it has 1 or more wildcards.")
				}
				return nil, ErrInvalidFormat
			} else {
				return &(WildcardScope{scope: *scopeRegex}), nil
			}
		} else if isNmapIPRange(line) {
			// Nmap octet range detection: must look like a.b.c.d with at least one range/comma
			nmapRange, err := parseNmapIPRange(line)
			if err != nil {
				return nil, ErrInvalidFormat
			}
			return nmapRange, nil
		} else {
			// Try to parse as CIDR
			if _, ipnet, err := net.ParseCIDR(line); err == nil {
				return ipnet, nil
			}
		}

	}

	// Try plain IP
	if ip := net.ParseIP(line); ip != nil {
		return &ip, nil
	}

	// Try URL (with basic validation)
	parsedURL, err := url.Parse(line)
	// If parsedURL.Opaque has content, then this is a data URI. Data URI's are not supported by hacker-scoper.
	parseAsURLFailed := (err != nil || parsedURL.Host == "" || parsedURL.Opaque != "")

	if parseAsURLFailed {
		// If the line doesn't already start with an "https://" prefix...
		if !strings.HasPrefix(line, "https://") {
			// Retry parsing but with a 'https://' prefix
			parsedURL, err = url.Parse("https://" + line)
			parseAsURLFailed = (err != nil || parsedURL.Host == "" || parsedURL.Opaque != "")
			if parseAsURLFailed {
				return nil, ErrInvalidFormat
			}
		} else {
			return nil, ErrInvalidFormat
		}
	}

	if !isScope {
		// scopes will never be URLs with IP hostnames. It doesn't make sense to check for IP hostnames in URLs for scopes
		// Try plain IP
		if ip := net.ParseIP(removePortFromHost(parsedURL)); ip != nil {
			myURLWithIPHostname := URLWithIPAddressHost{rawURL: line, IPhost: ip}
			return &myURLWithIPHostname, nil
		} else {
			return parsedURL, nil
		}
	} else {
		if parsedURL.Path == "" || parsedURL.Path == "/" {
			return removePortFromHost(parsedURL), nil
		} else {
			if !chainMode {
				warning("The text \"" + line + "\" was given as a scope, but it contains the path \"" + parsedURL.Path + "\". In order to properly match paths in your scope you have to use regex. This scope has been ignored.")
			}
			return nil, ErrInvalidFormat
		}

	}

}

// ParseAllLines processes each line individually, returning:
// - A slice of parsed objects (interface{} holding *net.IPNet, net.IP, or *url.URL)
// - An error if no lines could be parsed as a scope, otherwise nil.
// isScopes should be true if the lines to be parsed are scopes.
func parseAllLines(lines []string, isScopes bool) ([]interface{}, error) {
	parsed := []interface{}{}

	numWorkers := runtime.NumCPU()
	inputChan := make(chan string, numWorkers)
	outputChan := make(chan parseResult, len(lines))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range inputChan {
				result, err := parseLine(line, isScopes)
				if err != nil {
					outputChan <- parseResult{value: result, line: line, err: err}
				} else {
					outputChan <- parseResult{value: result, line: "", err: err}
				}
			}
		}()
	}

	// Feed lines to workers
	go func() {
		for _, line := range lines {
			inputChan <- line
		}
		close(inputChan)
	}()

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(outputChan)
	}()

	for res := range outputChan {
		if res.err != nil {
			if !chainMode {
				warning("Unable to parse line: \"" + res.line + "\"")
			}
		} else if res.value != nil {
			parsed = append(parsed, res.value)
		}
	}

	if len(parsed) == 0 {
		return nil, errors.New("unable to parse any lines as scopes")
	}
	return parsed, nil
}

func isInscope(inscopeScopes *[]interface{}, target *interface{}, explicitLevel *int) (result bool) {

	// Here we use a switch-case on the type of target. So target is processed differently depending on which variable type it is.

	switch assertedTarget := (*target).(type) {
	// If the target is an IP Address...
	case *net.IP:
		return isInscopeIP(assertedTarget, inscopeScopes, explicitLevel)
	case *URLWithIPAddressHost:
		return isInscopeIP(&assertedTarget.IPhost, inscopeScopes, explicitLevel)

	// If the target is a URL...
	case *url.URL:
		for i := range *inscopeScopes {
			// We're only interested in comparing URL targets against URL scopes, and regex.
			switch assertedScope := (*inscopeScopes)[i].(type) {
			// If the i scope is a URL...
			case string:
				switch *explicitLevel {
				case 1:
					//if x is a subdomain of y
					//ex: wordpress.example.com with a scope of *.example.com will give a match
					//we DON'T do it by splitting on dots and matching, because that would cause errors with domains that have two top-level-domains (gov.br for example)
					result = strings.HasSuffix(removePortFromHost(assertedTarget), assertedScope)

				case 2, 3:
					result = removePortFromHost(assertedTarget) == assertedScope
				}

			case *WildcardScope:
				if *explicitLevel != 3 {
					// If the i scope is a Wildcard Scope...
					//if the current target host matches the regex...
					result = (assertedScope.scope).MatchString(removePortFromHost(assertedTarget))
				}

			case *regexp.Regexp:
				// If the i scope is a regex...
				//if the current target matches the regex...
				result = assertedScope.MatchString(assertedTarget.String())

			}
			if result {
				return result
			}
		}
	}

	return false
}

func isInscopeIP(targetIP *net.IP, inscopeScopes *[]interface{}, explicitLevel *int) (result bool) {
	if *explicitLevel == 3 {
		// For each scope in inscopeScopes...
		for i := range *inscopeScopes {
			// We're only interested in comparing IP targets against IP addresses.
			// CIDR scopes are disabled in --explicit-level=3
			switch assertedScope := (*inscopeScopes)[i].(type) {

			// If the i scope is an IP Address...
			case *net.IP:
				result = assertedScope.Equal(*targetIP)
			}
			if result {
				return result
			}
		}
		return false
	} else {
		// For each scope in inscopeScopes...
		for i := range *inscopeScopes {
			// We're only interested in comparing IP targets against CIDR networks and IP addresses.
			switch assertedScope := (*inscopeScopes)[i].(type) {
			// If the i scope is a CIDR network...
			case *net.IPNet:
				result = assertedScope.Contains(*targetIP)

			// If the i scope is an IP Address...
			case *net.IP:
				result = assertedScope.Equal(*targetIP)

			case *NmapIPRange:
				ip := (*targetIP).To4()
				if ip == nil {
					continue
				}
				result = true
				for i := range 4 {
					found := false
					for _, v := range assertedScope.Octets[i] {
						if ip[i] == v {
							found = true
							break
						}
					}
					if !found {
						result = false
						break
					}
				}

			}
			if result {
				return result
			}
		}
		return false
	}
}

func isNmapIPRange(line string) bool {
	// Quick heuristic: must have 3 dots and at least one '-' or ','
	if strings.Count(line, ".") != 3 {
		return false
	}

	// Return false if line contains any a-z or A-Z letters
	if strings.IndexFunc(line, unicode.IsLetter) != -1 {
		return false
	}

	return strings.ContainsAny(line, "-,")
}

func parseNmapIPRange(line string) (*NmapIPRange, error) {
	parts := strings.Split(line, ".")
	if len(parts) != 4 {
		return nil, errors.New("invalid Nmap IP range format")
	}
	var octets [4][]uint8
	for i, part := range parts {
		vals, err := parseNmapOctet(part)
		if err != nil {
			return nil, err
		}
		octets[i] = vals
	}
	return &NmapIPRange{Octets: octets, Raw: line}, nil
}

func parseNmapOctet(part string) ([]uint8, error) {
	var vals []uint8
	for _, seg := range strings.Split(part, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "-" {
			seg = "0-255"
		}
		if strings.Contains(seg, "-") {
			bounds := strings.SplitN(seg, "-", 2)
			low := uint8(0)
			high := uint8(255)
			if bounds[0] != "" {
				l, err := strconv.Atoi(bounds[0])
				if err != nil || l < 0 || l > 255 {
					return nil, errors.New("invalid octet range")
				}
				low = uint8(l)
			}
			if bounds[1] != "" {
				h, err := strconv.Atoi(bounds[1])
				if err != nil || h < 0 || h > 255 {
					return nil, errors.New("invalid octet range")
				}
				high = uint8(h)
			}
			if low > high {
				return nil, errors.New("octet range low > high")
			}
			for v := low; ; v++ {
				vals = append(vals, v)
				if v == high {
					break
				}
			}
		} else {
			v, err := strconv.Atoi(seg)
			if err != nil || v < 0 || v > 255 {
				return nil, errors.New("invalid octet value")
			}
			vals = append(vals, uint8(v))
		}
	}
	return vals, nil
}

// Function to extract company names only
func extractCompanyNames(jsonPath string) ([]string, error) {
	file, err := os.Open(jsonPath) // #nosec G304 -- Intended behavior
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var partial PartialFirebounty
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&partial); err != nil {
		return nil, err
	}

	names := make([]string, len(partial.Pgms))
	for i, p := range partial.Pgms {
		names[i] = p.Name
	}
	return names, nil
}

// Efficiently load a single Program by index from the firebounty JSON
func loadProgramByIndex(jsonPath string, index int) (*Program, error) {
	file, err := os.Open(jsonPath) // #nosec G304 -- Intended behavior
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a decoder and seek to the "pgms" array
	decoder := json.NewDecoder(file)

	// Advance to the "pgms" key
	for {
		t, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if t == "pgms" {
			break
		}
	}

	// Read the start of the array
	if _, err := decoder.Token(); err != nil { // should be json.Delim('[')
		return nil, err
	}

	// Iterate through the array until the desired index
	for i := 0; decoder.More(); i++ {
		var prog Program
		if err := decoder.Decode(&prog); err != nil {
			return nil, err
		}
		if i == index {
			return &prog, nil
		}
	}

	return nil, errors.New("program index out of range")
}
