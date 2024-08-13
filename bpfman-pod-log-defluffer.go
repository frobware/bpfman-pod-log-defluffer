// Defluff is a command-line tool designed to improve the readability
// of JSON log entries (for bpfman operator and daemon output).
//
// It was created to address the challenge of interpreting dense,
// unformatted logs, which can often appear as a giant wall of text.
//
// By default, Defluff outputs each key-value pair on a new line,
// making logs easier to scan and interpret. For those who prefer a
// more compact format, a single-line output option is available via
// the `-s` flag. This option not only condenses the output into a
// single line but also strips out many JSON meta characters such as
// braces, brackets, and commas, providing a more streamlined view of
// the log content. Additionally, the tool sorts the fields of log
// entries case-insensitively, further enhancing readability.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

var brokenPipeDetected bool

// safePrint handles printing to os.Stdout and gracefully handles
// broken pipe errors.
func safePrint(format string, a ...interface{}) error {
	if brokenPipeDetected {
		return io.ErrClosedPipe
	}

	_, err := fmt.Fprintf(os.Stdout, format, a...)
	if err != nil {
		if isBrokenPipe(err) {
			brokenPipeDetected = true
			return err
		}
		fmt.Fprintln(os.Stderr, "Error writing output:", err)
		os.Exit(1)
	}

	return nil
}

// isBrokenPipe checks if the error is a broken pipe error.
func isBrokenPipe(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		if pathErr.Err == syscall.EPIPE {
			return true
		}
	}
	return false
}

// extractField extracts and removes a field from a map if it exists.
func extractField(data *map[string]interface{}, key string) string {
	if value, found := (*data)[key]; found {
		delete(*data, key)
		return fmt.Sprintf("%v", value)
	}
	return ""
}

// flattenMap flattens a nested map into a map with key paths as keys.
func flattenMap(data map[string]interface{}, prefix string) map[string]interface{} {
	flatMap := make(map[string]interface{})
	for k, v := range data {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		switch child := v.(type) {
		case map[string]interface{}:
			nestedMap := flattenMap(child, key)
			for nk, nv := range nestedMap {
				flatMap[nk] = nv
			}
		default:
			flatMap[key] = v
		}
	}
	return flatMap
}

// processBPFDaemonLog handles log entries from the bpfdaemon, which
// are JSON formatted.
func processBPFDaemonLog(jsonData map[string]interface{}, singleline bool) error {
	specialFields := []string{
		strings.TrimSpace(extractField(&jsonData, "ts")),
		strings.TrimSpace(extractField(&jsonData, "level")),
		strings.TrimSpace(extractField(&jsonData, "logger")),
	}

	msg := strings.TrimSpace(extractField(&jsonData, "msg"))

	// Prepare to flatten the remaining JSON data.
	flattened := flattenMap(jsonData, "")
	var pairs []string
	for k, v := range flattened {
		if singleline {
			pairs = append(pairs, fmt.Sprintf("%v=%q", k, v))
		} else {
			pairs = append(pairs, fmt.Sprintf("%v: %v", k, v))
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		return strings.ToLower(pairs[i]) < strings.ToLower(pairs[j])
	})

	// Build the log line with special fields.
	var buffer bytes.Buffer
	for _, field := range specialFields {
		if field != "" {
			if buffer.Len() > 0 {
				buffer.WriteString(" ")
			}
			buffer.WriteString(field)
		}
	}

	logLineStr := strings.TrimSpace(buffer.String())
	if msg != "" {
		logLineStr += ": \"" + msg + "\""
	}

	if err := safePrint("%s", logLineStr); err != nil {
		return err
	}

	if singleline {
		if err := safePrint(" %s\n", strings.Join(pairs, " ")); err != nil {
			return err
		}
	} else {
		if err := safePrint("\n"); err != nil {
			return err
		}
		for _, pair := range pairs {
			if err := safePrint("\t%s\n", pair); err != nil {
				return err
			}
		}
	}

	if !singleline {
		if err := safePrint("\n"); err != nil {
			return err
		}
	}

	return nil
}

// processOperatorLog handles log entries that follow a different
// format.
func processOperatorLog(line string, singleline bool) error {
	// Split the line at the first JSON opening brace.
	parts := strings.SplitN(line, "{", 2)
	if len(parts) < 2 {
		// No JSON part found, print the original line.
		if err := safePrint("%s\n", line); err != nil {
			return err
		}
		if !singleline {
			return safePrint("\n")
		}
		return nil
	}

	prefix := parts[0]
	jsonPart := "{" + parts[1]

	// Output the log prefix (timestamp, level, etc.).
	if err := safePrint("%s", strings.TrimSpace(prefix)); err != nil {
		return err
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonPart), &jsonData); err != nil {
		// If JSON is invalid, just print the original line.
		if err := safePrint("%s\n", line); err != nil {
			return err
		}
		if !singleline {
			return safePrint("\n")
		}
		return nil
	}

	// Ensure we start the JSON output on a new line in multiline
	// mode.
	if !singleline {
		if err := safePrint("\n"); err != nil {
			return err
		}
	}

	flattened := flattenMapWithArrays(jsonData, "", singleline)

	keys := make([]string, 0, len(flattened))
	for k := range flattened {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})

	var output strings.Builder
	for _, k := range keys {
		v := flattened[k]
		if singleline {
			output.WriteString(fmt.Sprintf(" %v=\"%v\"", k, formatValue(v)))
		} else {
			output.WriteString(fmt.Sprintf("\t%v: %v\n", k, formatValue(v)))
		}
	}

	return safePrint("%s\n", output.String())
}

// formatValue formats the value appropriately, especially for
// booleans and other types.
func formatValue(value interface{}) string {
	switch v := value.(type) {
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// flattenMapWithArrays flattens a nested map into dot-separated key
// paths, but retains arrays.
func flattenMapWithArrays(data map[string]interface{}, prefix string, singleline bool) map[string]interface{} {
	flatMap := make(map[string]interface{})

	for k, v := range data {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		switch child := v.(type) {
		case map[string]interface{}:
			// Recursively flatten nested maps.
			nestedMap := flattenMapWithArrays(child, key, singleline)
			for nk, nv := range nestedMap {
				flatMap[nk] = nv
			}
		case []interface{}:
			if singleline {
				// Handle arrays as single-line,
				// comma-separated values.
				arrayItems := make([]string, len(child))
				for i, item := range child {
					arrayItems[i] = fmt.Sprintf("%v", item)
				}
				flatMap[key] = fmt.Sprintf("[%s]", strings.Join(arrayItems, ", "))
			} else {
				// Retain array structure with
				// indentation.
				for i, item := range child {
					arrayKey := fmt.Sprintf("%s[%d]", key, i)
					if mapItem, ok := item.(map[string]interface{}); ok {
						// Flatten map items
						// inside the array.
						nestedMap := flattenMapWithArrays(mapItem, arrayKey, singleline)
						for nk, nv := range nestedMap {
							flatMap[nk] = nv
						}
					} else {
						flatMap[arrayKey] = item
					}
				}
			}
		default:
			flatMap[key] = v
		}
	}

	return flatMap
}

// processLogLine determines which log processing function to call
// based on the input format.
func processLogLine(line string, singleline bool) error {
	// Check if the line starts with '{', indicating it's likely a
	// JSON log from bpfdaemon.
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		// Attempt to parse the line as JSON.
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(line), &jsonData); err == nil {
			// Successfully parsed as JSON, so it's likely
			// a bpfdaemon log.
			return processBPFDaemonLog(jsonData, singleline)
		}
	}

	// If it's not a JSON log from bpfdaemon, handle it as an
	// operator log or another format.
	return processOperatorLog(line, singleline)
}

func main() {
	signal.Ignore(syscall.SIGPIPE)

	emitOriginal := flag.Bool("o", false, "Output the original, unfiltered input")
	singleline := flag.Bool("s", false, "Output key-value pairs on a single line")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		if *emitOriginal {
			if err := safePrint("%s\n", line); err != nil {
				return // Exit gracefully on broken pipe
			}
		}

		if err := processLogLine(line, *singleline); err != nil {
			return // Exit gracefully on broken pipe
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input:", err)
		os.Exit(1)
	}
}
