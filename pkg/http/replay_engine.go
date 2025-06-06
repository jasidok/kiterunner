package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/assetnote/kiterunner2/pkg/log"
)

// ReplayConfig holds configuration for the replay engine
type ReplayConfig struct {
	// Enabled determines whether the replay engine is enabled
	Enabled bool
	// OutputDirectory is the directory where replay files will be stored
	OutputDirectory string
	// FFUFEnabled determines whether to send requests to FFUF
	FFUFEnabled bool
	// FFUFPath is the path to the FFUF executable
	FFUFPath string
	// FFUFWordlist is the path to the wordlist to use with FFUF
	FFUFWordlist string
	// ParamMinerEnabled determines whether to send requests to Param Miner
	ParamMinerEnabled bool
	// ParamMinerPath is the path to the Param Miner script
	ParamMinerPath string
	// CustomFuzzerEnabled determines whether to send requests to a custom fuzzer
	CustomFuzzerEnabled bool
	// CustomFuzzerCommand is the command to execute for the custom fuzzer
	CustomFuzzerCommand string
	// SuccessStatusCodes are the status codes that indicate a successful request
	SuccessStatusCodes []int
	// BypassDetectionThreshold is the threshold for detecting a bypass
	BypassDetectionThreshold int
	// MaxRequestsToStore is the maximum number of requests to store
	MaxRequestsToStore int
}

// DefaultReplayConfig returns a default replay configuration
func DefaultReplayConfig() *ReplayConfig {
	return &ReplayConfig{
		Enabled:                  true,
		OutputDirectory:          "replay_output",
		FFUFEnabled:              true,
		FFUFPath:                 "ffuf",
		FFUFWordlist:             "/usr/share/wordlists/dirb/common.txt",
		ParamMinerEnabled:        false,
		ParamMinerPath:           "",
		CustomFuzzerEnabled:      false,
		CustomFuzzerCommand:      "",
		SuccessStatusCodes:       []int{200, 201, 202, 203, 204, 206, 207},
		BypassDetectionThreshold: 3,
		MaxRequestsToStore:       1000,
	}
}

// ReplayRequest represents a request to be replayed
type ReplayRequest struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body,omitempty"`
	OriginalStatus  int               `json:"original_status"`
	BypassedStatus  int               `json:"bypassed_status"`
	BypassTechnique string            `json:"bypass_technique"`
	Timestamp       time.Time         `json:"timestamp"`
}

// ReplayEngine handles replaying requests to follow-up fuzzers
type ReplayEngine struct {
	Config           *ReplayConfig
	BypassedRequests []ReplayRequest
	mutex            sync.RWMutex
}

// NewReplayEngine creates a new replay engine
func NewReplayEngine(config *ReplayConfig) (*ReplayEngine, error) {
	if config == nil {
		config = DefaultReplayConfig()
	}

	// Create output directory if it doesn't exist
	if config.Enabled && config.OutputDirectory != "" {
		if err := os.MkdirAll(config.OutputDirectory, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	return &ReplayEngine{
		Config:           config,
		BypassedRequests: make([]ReplayRequest, 0),
	}, nil
}

// AddBypassedRequest adds a bypassed request to the replay engine
func (r *ReplayEngine) AddBypassedRequest(req ReplayRequest) {
	if !r.Config.Enabled {
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Add the request to the list
	r.BypassedRequests = append(r.BypassedRequests, req)

	// Trim the list if it exceeds the maximum size
	if len(r.BypassedRequests) > r.Config.MaxRequestsToStore {
		r.BypassedRequests = r.BypassedRequests[len(r.BypassedRequests)-r.Config.MaxRequestsToStore:]
	}

	// Save the request to a file
	r.saveRequestToFile(req)

	// Send the request to follow-up fuzzers
	go r.sendToFollowUpFuzzers(req)
}

// IsSuccessStatusCode checks if a status code indicates a successful request
func (r *ReplayEngine) IsSuccessStatusCode(statusCode int) bool {
	for _, code := range r.Config.SuccessStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// DetectBypass detects if a request has bypassed security controls
func (r *ReplayEngine) DetectBypass(originalStatus, bypassedStatus int) bool {
	// If the original status was a failure and the bypassed status is a success
	return !r.IsSuccessStatusCode(originalStatus) && r.IsSuccessStatusCode(bypassedStatus)
}

// saveRequestToFile saves a request to a file
func (r *ReplayEngine) saveRequestToFile(req ReplayRequest) {
	if r.Config.OutputDirectory == "" {
		return
	}

	// Create a filename based on the URL and timestamp
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		log.Error().Err(err).Str("url", req.URL).Msg("Failed to parse URL for replay file")
		return
	}

	hostname := parsedURL.Hostname()
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s_%s_%d_%s.json", hostname, req.Method, req.BypassedStatus, timestamp)
	filepath := filepath.Join(r.Config.OutputDirectory, filename)

	// Marshal the request to JSON
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal request to JSON")
		return
	}

	// Write the file
	if err := ioutil.WriteFile(filepath, data, 0644); err != nil {
		log.Error().Err(err).Str("file", filepath).Msg("Failed to write replay file")
		return
	}

	log.Info().Str("file", filepath).Msg("Saved bypassed request to file")
}

// sendToFollowUpFuzzers sends a request to follow-up fuzzers
func (r *ReplayEngine) sendToFollowUpFuzzers(req ReplayRequest) {
	// Send to FFUF
	if r.Config.FFUFEnabled && r.Config.FFUFPath != "" {
		r.sendToFFUF(req)
	}

	// Send to Param Miner
	if r.Config.ParamMinerEnabled && r.Config.ParamMinerPath != "" {
		r.sendToParamMiner(req)
	}

	// Send to custom fuzzer
	if r.Config.CustomFuzzerEnabled && r.Config.CustomFuzzerCommand != "" {
		r.sendToCustomFuzzer(req)
	}
}

// sendToFFUF sends a request to FFUF
func (r *ReplayEngine) sendToFFUF(req ReplayRequest) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		log.Error().Err(err).Str("url", req.URL).Msg("Failed to parse URL for FFUF")
		return
	}

	// Create a temporary file for the headers
	headersFile, err := ioutil.TempFile("", "ffuf-headers-*.txt")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temporary file for FFUF headers")
		return
	}
	defer os.Remove(headersFile.Name())

	// Write headers to the file
	for key, value := range req.Headers {
		if _, err := headersFile.WriteString(fmt.Sprintf("%s: %s\n", key, value)); err != nil {
			log.Error().Err(err).Msg("Failed to write headers to temporary file")
			return
		}
	}
	headersFile.Close()

	// Construct the FFUF command
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	outputFile := filepath.Join(r.Config.OutputDirectory, fmt.Sprintf("ffuf_%s_%s.json",
		parsedURL.Hostname(), time.Now().Format("20060102-150405")))

	args := []string{
		"-u", baseURL + "/FUZZ",
		"-w", r.Config.FFUFWordlist,
		"-H", fmt.Sprintf("@%s", headersFile.Name()),
		"-o", outputFile,
		"-of", "json",
		"-c",
	}

	// Add request method if not GET
	if req.Method != "GET" {
		args = append(args, "-X", req.Method)
	}

	// Add request body if present
	if req.Body != "" {
		bodyFile, err := ioutil.TempFile("", "ffuf-body-*.txt")
		if err != nil {
			log.Error().Err(err).Msg("Failed to create temporary file for FFUF body")
			return
		}
		defer os.Remove(bodyFile.Name())

		if _, err := bodyFile.WriteString(req.Body); err != nil {
			log.Error().Err(err).Msg("Failed to write body to temporary file")
			return
		}
		bodyFile.Close()

		args = append(args, "-d", fmt.Sprintf("@%s", bodyFile.Name()))
	}

	// Execute FFUF
	cmd := exec.Command(r.Config.FFUFPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Info().Str("url", req.URL).Msg("Sending bypassed request to FFUF")
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg("Failed to execute FFUF")
		return
	}

	log.Info().Str("output", outputFile).Msg("FFUF completed successfully")
}

// sendToParamMiner sends a request to Param Miner
func (r *ReplayEngine) sendToParamMiner(req ReplayRequest) {
	// Create a temporary file for the request
	requestFile, err := ioutil.TempFile("", "param-miner-req-*.txt")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temporary file for Param Miner request")
		return
	}
	defer os.Remove(requestFile.Name())

	// Write the request to the file
	requestFile.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", req.Method, req.URL))
	for key, value := range req.Headers {
		requestFile.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}
	requestFile.WriteString("\n")
	if req.Body != "" {
		requestFile.WriteString(req.Body)
	}
	requestFile.Close()

	// Construct the Param Miner command
	outputFile := filepath.Join(r.Config.OutputDirectory, fmt.Sprintf("param_miner_%s.txt",
		time.Now().Format("20060102-150405")))

	args := []string{
		"-r", requestFile.Name(),
		"-o", outputFile,
	}

	// Execute Param Miner
	cmd := exec.Command(r.Config.ParamMinerPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Info().Str("url", req.URL).Msg("Sending bypassed request to Param Miner")
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg("Failed to execute Param Miner")
		return
	}

	log.Info().Str("output", outputFile).Msg("Param Miner completed successfully")
}

// sendToCustomFuzzer sends a request to a custom fuzzer
func (r *ReplayEngine) sendToCustomFuzzer(req ReplayRequest) {
	// Create a temporary file for the request
	requestFile, err := ioutil.TempFile("", "custom-fuzzer-req-*.json")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temporary file for custom fuzzer request")
		return
	}
	defer os.Remove(requestFile.Name())

	// Marshal the request to JSON
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal request to JSON")
		return
	}

	// Write the request to the file
	if _, err := requestFile.Write(data); err != nil {
		log.Error().Err(err).Msg("Failed to write request to temporary file")
		return
	}
	requestFile.Close()

	// Replace placeholders in the command
	command := strings.ReplaceAll(r.Config.CustomFuzzerCommand, "{REQUEST_FILE}", requestFile.Name())
	command = strings.ReplaceAll(command, "{URL}", req.URL)
	command = strings.ReplaceAll(command, "{METHOD}", req.Method)
	command = strings.ReplaceAll(command, "{OUTPUT_DIR}", r.Config.OutputDirectory)

	// Split the command into command and arguments
	parts := strings.Fields(command)
	if len(parts) == 0 {
		log.Error().Msg("Invalid custom fuzzer command")
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Info().Str("url", req.URL).Msg("Sending bypassed request to custom fuzzer")
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg("Failed to execute custom fuzzer")
		return
	}

	log.Info().Str("stdout", stdout.String()).Msg("Custom fuzzer completed successfully")
}

// GetBypassedRequests returns all bypassed requests
func (r *ReplayEngine) GetBypassedRequests() []ReplayRequest {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]ReplayRequest, len(r.BypassedRequests))
	copy(result, r.BypassedRequests)
	return result
}

// ClearBypassedRequests clears all bypassed requests
func (r *ReplayEngine) ClearBypassedRequests() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.BypassedRequests = make([]ReplayRequest, 0)
}

// SaveAllRequestsToFile saves all bypassed requests to a single file
func (r *ReplayEngine) SaveAllRequestsToFile(filename string) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Marshal the requests to JSON
	data, err := json.MarshalIndent(r.BypassedRequests, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal requests to JSON: %v", err)
	}

	// Write the file
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	log.Info().Str("file", filename).Int("count", len(r.BypassedRequests)).Msg("Saved all bypassed requests to file")
	return nil
}
