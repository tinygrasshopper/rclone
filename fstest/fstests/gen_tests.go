// +build ignore

// Make the test files from fstests.go
package main

import (
	"bufio"
	"html/template"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Search fstests.go and return all the test function names
func findTestFunctions() []string {
	fns := []string{}
	matcher := regexp.MustCompile(`^func\s+(Test.*?)\(`)

	in, err := os.Open("fstests.go")
	if err != nil {
		log.Fatalf("Couldn't open fstests.go: %v", err)
	}
	defer in.Close()

	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		matches := matcher.FindStringSubmatch(line)
		if len(matches) > 0 {
			fns = append(fns, matches[1])
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}
	return fns
}

// Data to substitute
type Data struct {
	Regenerate  string
	FsName      string
	UpperFsName string
	TestName    string
	ObjectName  string
	Fns         []string
}

var testProgram = `
// Test {{ .UpperFsName }} filesystem interface
//
// Automatically generated - DO NOT EDIT
// Regenerate with: {{ .Regenerate }}
package {{ .FsName }}_test

import (
	"testing"

	"github.com/tinygrasshopper/rclone/fs"
	"github.com/tinygrasshopper/rclone/fstest/fstests"
	"github.com/tinygrasshopper/rclone/{{ .FsName }}"
)

func init() {
	fstests.NilObject = fs.Object((*{{ .FsName }}.FsObject{{ .ObjectName }})(nil))
	fstests.RemoteName = "{{ .TestName }}"
}

// Generic tests for the Fs
{{ range $fn := .Fns }}func {{ $fn }}(t *testing.T){ fstests.{{ $fn }}(t) }
{{ end }}
`

// Generate test file piping it through gofmt
func generateTestProgram(t *template.Template, fns []string, Fsname string) {
	fsname := strings.ToLower(Fsname)
	TestName := "Test" + Fsname + ":"
	outfile := "../../" + fsname + "/" + fsname + "_test.go"
	// Find last capitalised group to be object name
	matcher := regexp.MustCompile(`([A-Z][a-z0-9]+)$`)
	matches := matcher.FindStringSubmatch(Fsname)
	if len(matches) == 0 {
		log.Fatalf("Couldn't find object name in %q", Fsname)
	}
	ObjectName := matches[1]

	if fsname == "local" {
		TestName = ""
	}

	data := Data{
		Regenerate:  "go run gen_tests.go or make gen_tests",
		FsName:      fsname,
		UpperFsName: Fsname,
		TestName:    TestName,
		ObjectName:  ObjectName,
		Fns:         fns,
	}

	cmd := exec.Command("gofmt")

	log.Printf("Writing %q", outfile)
	out, err := os.Create(outfile)
	if err != nil {
		log.Fatal(err)
	}
	cmd.Stdout = out

	gofmt, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}
	if err = t.Execute(gofmt, data); err != nil {
		log.Fatal(err)
	}
	if err = gofmt.Close(); err != nil {
		log.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	if err = out.Close(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	fns := findTestFunctions()
	t := template.Must(template.New("main").Parse(testProgram))
	generateTestProgram(t, fns, "Local")
	generateTestProgram(t, fns, "Swift")
	generateTestProgram(t, fns, "S3")
	generateTestProgram(t, fns, "Drive")
	generateTestProgram(t, fns, "GoogleCloudStorage")
	generateTestProgram(t, fns, "Dropbox")
	log.Printf("Done")
}
