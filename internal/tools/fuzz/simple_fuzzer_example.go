package fuzz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghostsecurity/reaper/internal/config"
	"github.com/ghostsecurity/reaper/internal/database/models"
	"github.com/ghostsecurity/reaper/internal/handlers/websocket"
	"github.com/ghostsecurity/reaper/internal/types"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

type Request struct {
	Method  string
	URL     string
	Body    string
	Headers map[string]string
}

const (
	maxWorkers        = 5
	defaultMaxSuccess = 10
	minIncrement      = 10
	maxIncrement      = 50
)

// Helper to check if an attack type is enabled
func isAttackEnabled(attack string, cfg config.AttackConfig) bool {
	switch attack {
	case "HP":
		return cfg.HP
	case "LP":
		return cfg.LP
	case "NP":
		return cfg.NP
	case "RPP":
		return cfg.RPP
	case "BPP":
		return cfg.BPP
	case "MR":
		return cfg.MR
	case "RPW":
		return cfg.RPW
	case "BPW":
		return cfg.BPW
	case "RPS":
		return cfg.RPS
	case "RPSPP":
		return cfg.RPSPP
	case "FUZZ":
		return cfg.FUZZ
	case "JSON":
		return cfg.JSON
	default:
		return false
	}
}

// AttackConfig defines the attack types to perform
type AttackConfig struct {
	HP, LP, NP      bool
	RPP, BPP        bool
	MR, RPW, BPW    bool
	RPS, RPSPP      bool
	JSON, ALL, FUZZ bool
}

var globalSensitiveParams []string

// func CreateAttack(hostname string, params []string, ws *websocket.Pool, db *gorm.DB, min, max, maxSuccess int) error {
func CreateAttack(hostname string, params []string, ws *websocket.Pool, db *gorm.DB, maxSuccess int, fuzzCookies bool, attackConfig config.AttackConfig) error {
	slog.Info("CreateAttack function called", "hostname", hostname, "params", params, "maxSuccess", maxSuccess, "fuzzCookies", fuzzCookies)

	// Set the global sensitive parameters
	globalSensitiveParams = params

	req := models.Request{
		Method: http.MethodPost,
	}

	// Get the most recent POST request for the endpoint
	res := db.Where(&req).
		Where("host LIKE ?", "%"+hostname+"%").
		Where("method = ?", req.Method).
		Order("created_at DESC").
		First(&req)

	if res.Error != nil {
		return fmt.Errorf("failed to find POST request for hostname %s: %w", hostname, res.Error)
	}

	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = fmt.Sprintf("https://%s%s", hostname, req.URL)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)
	var successCount int32
	done := make(chan struct{})
	var once sync.Once

	// Worker function
	runWorker := func(request models.Request) {
		defer wg.Done()
		defer func() { <-semaphore }()
		status, err := _sendRequest(request, ws, db)
		if err != nil {
			slog.Error("Request failed:", "Error", err)
		} else if status >= http.StatusOK && status < http.StatusMultipleChoices {
			newCount := atomic.AddInt32(&successCount, 1)
			if int(newCount) >= maxSuccess {
				slog.Info("Max success count reached:", maxSuccess)
				once.Do(func() { close(done) })
			}
		}
	}

	// Generate and send requests
	attackGenerators := map[string]func(models.Request) []models.Request{
		"HP":    generateHighPrivilegedRequests,
		"LP":    generateLowPrivilegedRequests,
		"NP":    generateNoPrivilegedRequests,
		"RPP":   generateRequestParameterPollution,
		"BPP":   generateBodyParameterPollution,
		"MR":    generateMethodReplacementRequests,
		"RPW":   generateRequestParameterWrapping,
		"BPW":   generateBodyParameterWrapping,
		"RPS":   generateRequestParameterSubstitution,
		"RPSPP": generateRequestParameterSubstitutionWithPollution,
		"FUZZ":  GenerateFuzzParams,
		"JSON":  generateJSONExtensionRequests,
	}

	for attackType, generator := range attackGenerators {
		if isAttackEnabled(attackType, attackConfig) {
			for _, req := range generator(req) {
				select {
				case <-done:
					return nil
				default:
					wg.Add(1)
					semaphore <- struct{}{}
					go runWorker(req)
				}
			}
		}
	}

	wg.Wait()

	slog.Info("Fuzz attack completed", "successCount", 0, "totalCount", 0)
	return nil
}

func createFuzzedRequest(originalReq *models.Request, key string, value int) *http.Request {
	var body map[string]interface{}
	err := json.Unmarshal([]byte(originalReq.Body), &body)
	if err != nil {
		slog.Error("Failed to parse body", "error", err)
	}

	// Update the specified key with the fuzzed value
	body[key] = value
	fuzzedBody, _ := json.Marshal(body)
	req, _ := http.NewRequest(originalReq.Method, originalReq.URL, strings.NewReader(string(fuzzedBody)))

	return req
}

func copyHeaders(req *http.Request, headers string) {
	for _, line := range strings.Split(headers, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

// Helper function to parse headers from a string to a map
func parseHeaders(headers string) map[string]string {
	headerMap := make(map[string]string)
	for _, line := range strings.Split(headers, "\n") {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			headerMap[parts[0]] = parts[1]
		}
	}
	return headerMap
}

// Helper function to convert headers from a map to a string
func headersToString(headerMap map[string]string) string {
	var headerLines []string
	for key, value := range headerMap {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", key, value))
	}
	return strings.Join(headerLines, "\n")
}

// Function to reconstruct the headers map back into a raw header string
func reconstructHeaders(headers map[string]string) string {
	var headerLines []string
	for key, value := range headers {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", key, value))
	}
	return strings.Join(headerLines, "\n")
}

// ModifyJWT generates dynamic JWTs based on input claims and fuzzes different combinations
func modifyJWT(tokenString string, newClaims map[string]interface{}) (string, error) {
	// Decode JWT
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode header and payload
	header, err := decodeBase64(parts[0])
	if err != nil {
		slog.Error("Failed to Decode Base64", "Error", err)
		return "", err
	}

	payload, err := decodeBase64(parts[1])
	if err != nil {
		slog.Error("Failed to Decode Base64", "Error", err)
		return "", err
	}

	// Modify the payload with new claims
	for key, value := range newClaims {
		payload[key] = value
	}

	// Re-encode header and payload
	encodedHeader, err := encodeBase64(header)
	if err != nil {
		slog.Error("failed to encode header:", "Error", err)
		return "", fmt.Errorf("failed to encode header:", "Error", err)
	}

	encodedPayload, err := encodeBase64(payload)
	if err != nil {
		slog.Error("failed to encode header:", "Error", err)
		return "", fmt.Errorf("failed to encode payload:", "Error", err)
	}

	// Return the modified token (without signature)
	return encodedHeader + "." + encodedPayload + "." + parts[2], nil
}

// Decode and encode helper functions
func decodeBase64(input string) (map[string]interface{}, error) {
	decoded, err := jwt.DecodeSegment(input)
	if err != nil {
		return nil, err
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal(decoded, &jsonData)
	return jsonData, err
}

func encodeBase64(data map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(encoded), nil
}

// Dynamic Claim Fuzzing for JWT
func generateFuzzedJWTs_HIGH(token string) []string {
	var fuzzedTokens []string
	claimPatterns := []map[string]interface{}{
		{"role": "admin"},
		{"role": "user"},
		{"role": "superadmin"},
		{"role": "moderator"},
		{"role": "moderator", "exp": time.Now().Add(5 * time.Hour).Unix()},
		{"admin": true},
		{"permissions": []string{"read", "write"}},
		{"permissions": []string{"delete"}, "iat": time.Now().Unix()},
		{"permissions": []string{"create", "read"}, "sub": "systemadmin"},
		{"sub": "adminuser", "permissions": []string{"admin"}},
		{"exp": time.Now().Add(24 * time.Hour).Unix()},
		{"sub": "testuser123"},
		{"iat": time.Now().Unix()},
		{"iat": -1000000}, // Invalid past timestamp

	}

	// Fuzz different combinations
	for _, pattern := range claimPatterns {
		modifiedToken, err := modifyJWT(token, pattern)
		if err == nil {
			fuzzedTokens = append(fuzzedTokens, modifiedToken)
		} else {
			slog.Error("Error modifying JWT:", "Error", err)
		}
	}

	// Return all fuzzed JWTs
	return fuzzedTokens
}

// Dynamic Claim Fuzzing for JWT
func generateFuzzedJWTs_LOW(token string) []string {
	var fuzzedTokens []string
	claimPatterns := []map[string]interface{}{
		// Different roles
		{"role": "user"},
		{"role": "guest"},
		{"role": "support"},

		// Boolean admin claim
		{"admin": false},
		{"admin": "None"}, // Invalid type

		// Permissions as an array of strings
		{"permissions": []string{"read", "write"}},
		{"permissions": []string{"read"}},
		{"permissions": []string{"write"}},
		{"permissions": []string{"admin"}},
		{"permissions": []string{"delete", "modify"}},
		{"permissions": []string{"create", "execute"}},

		// Expiration time variations
		{"exp": time.Now().Add(24 * time.Hour).Unix()},
		{"exp": time.Now().Add(-24 * time.Hour).Unix()},
		{"exp": time.Now().Add(1 * time.Minute).Unix()},

		// Subject variations
		{"sub": "developer"},
		{"sub": "unknownuser"},

		// Combination of claims
		{"admin": false, "sub": "testuser123"},
		{"role": "guest", "iat": time.Now().Add(-30 * time.Minute).Unix()},
		{"role": "user", "exp": time.Now().Add(24 * time.Hour).Unix(), "permissions": []string{"read"}},
	}

	// Fuzz different combinations
	for _, pattern := range claimPatterns {
		modifiedToken, err := modifyJWT(token, pattern)
		if err == nil {
			fuzzedTokens = append(fuzzedTokens, modifiedToken)
		} else {
			slog.Error("Error modifying JWT:", "Error", err)
		}
	}

	// Return all fuzzed JWTs
	return fuzzedTokens
}

// Function to generate low-privileged requests by fuzzing JWTs
func generateHighPrivilegedRequests(req models.Request) []models.Request {
	// Log original request headers for debugging
	headers := parseHeaders(req.Headers)

	// Check if Authorization header exists and modify the token
	if authHeader, exists := headers["Authorization"]; exists && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Generate fuzzed JWTs by modifying claims dynamically
		fuzzedTokens := generateFuzzedJWTs_HIGH(token)

		// Replace the original JWT with each fuzzed version and create a new request for each
		var modifiedRequests []models.Request
		for _, fuzzedToken := range fuzzedTokens {
			// Modify the Authorization header with the fuzzed token
			headers["Authorization"] = "Bearer " + fuzzedToken

			req.Headers = reconstructHeaders(headers)
			modifiedRequests = append(modifiedRequests, req)
		}
		// Return the list of requests with fuzzed tokens
		return modifiedRequests
	}

	// Return the original request if no Authorization header was found
	return []models.Request{req}
}

func generateLowPrivilegedRequests(req models.Request) []models.Request {
	headers := parseHeaders(req.Headers)
	// Check if Authorization header exists and modify the token
	if authHeader, exists := headers["Authorization"]; exists && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")

		fuzzedTokens := generateFuzzedJWTs_LOW(token)

		var modifiedRequests []models.Request
		for _, fuzzedToken := range fuzzedTokens {
			headers["Authorization"] = "Bearer " + fuzzedToken

			req.Headers = reconstructHeaders(headers)
			modifiedRequests = append(modifiedRequests, req)
		}
		return modifiedRequests
	}

	return []models.Request{req}
}

func generateNoPrivilegedRequests(req models.Request) []models.Request {
	headerMap := parseHeaders(req.Headers)

	privilegedHeaders := []string{
		"Authorization",
		"X-Access-Token",
		"X-Auth-Token",
		"Authorization-Token", // Add other known privileged headers here
		"Cookie",
	}

	// Remove privileged headers
	for _, header := range privilegedHeaders {
		delete(headerMap, header)
	}

	// Remove any header starting with "X-"
	for key := range headerMap {
		if strings.HasPrefix(key, "X-") {
			delete(headerMap, key)
		}
	}

	req.Headers = headersToString(headerMap)

	return []models.Request{req}
}

// generateRequestParameterPollution handles URL query parameter pollution.
func generateRequestParameterPollution(req models.Request) []models.Request {
	parsedParams := parseBodyToParams(strings.TrimPrefix(req.URL, "?"))
	for key, values := range parsedParams {
		parsedParams[key] = addPollutedValues(values)
	}
	req.URL = "?" + paramsToBody(parsedParams)
	return []models.Request{req}
}

// generateBodyParameterPollution handles JSON or query-string body pollution.
func generateBodyParameterPollution(req models.Request) []models.Request {
	if isJSON(req.Body) {
		req.Body = polluteJSONBody(req.Body)
	} else {
		req.Body = polluteQueryString(req.Body)
	}
	return []models.Request{req}
}

// polluteQueryString handles query string pollution.
func polluteQueryString(body string) string {
	parsedParams := parseBodyToParams(body)
	for key, values := range parsedParams {
		parsedParams[key] = addPollutedValues(values)
	}
	return paramsToBody(parsedParams)
}

// paramsToBody converts the map of parameters back into a query string.
func paramsToBody(params map[string][]string) string {
	var bodyParts []string
	for key, values := range params {
		for _, value := range values {
			bodyParts = append(bodyParts, key+"="+value)
		}
	}
	return strings.Join(bodyParts, "&")
}

// isJSON checks if the body is a valid JSON string.
func isJSON(body string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(body), &js) == nil
}

// polluteJSONBody dynamically modifies JSON body values.
func polluteJSONBody(body string) string {
	var jsonBody map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonBody); err != nil {
		return body
	}

	for key, value := range jsonBody {
		switch v := value.(type) {
		case string:
			newValue := "" + v
			if rand.Intn(2) == 0 {
				jsonBody[key] = newValue
			} else {
				jsonBody[key] = []interface{}{v, newValue}
			}
		case float64:
			newValue := v + rand.Float64()*10
			if rand.Intn(2) == 0 {
				jsonBody[key] = newValue
			} else {
				jsonBody[key] = []interface{}{v, newValue}
			}
		case bool:
			newValue := !v
			if rand.Intn(2) == 0 {
				jsonBody[key] = newValue
			} else {
				jsonBody[key] = []interface{}{v, newValue}
			}
		}
	}

	pollutedBody, err := json.Marshal(jsonBody)
	if err != nil {
		return body
	}
	return string(pollutedBody)
}

// addPollutedValues dynamically generates polluted values for query parameters.
func addPollutedValues(values []string) []string {
	rand.Seed(time.Now().UnixNano())
	var pollutedValues []string
	for _, value := range values {
		if num, err := strconv.ParseFloat(value, 64); err == nil {
			newValue := strconv.FormatFloat(num+rand.Float64()*10, 'f', 2, 64)
			if rand.Intn(2) == 0 {
				pollutedValues = append(pollutedValues, newValue)
			} else {
				pollutedValues = append(pollutedValues, value, newValue)
			}
		} else if value == "true" || value == "false" {
			newValue := strconv.FormatBool(value == "false")
			if rand.Intn(2) == 0 {
				pollutedValues = append(pollutedValues, newValue)
			} else {
				pollutedValues = append(pollutedValues, value, newValue)
			}
		} else {
			newValue := value + "" + randomString(5)
			if rand.Intn(2) == 0 {
				pollutedValues = append(pollutedValues, newValue)
			} else {
				pollutedValues = append(pollutedValues, value, newValue)
			}
		}
	}
	return pollutedValues
}

// randomString generates a random alphanumeric string of the given length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateMethodReplacementRequests(req models.Request) []models.Request {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
		"CONNECT", // Non-standard methods
		"TRACE",   // Non-standard methods
		"MERGE",   // Non-standard methods
	}

	var requests []models.Request
	for _, method := range methods {
		fuzzedReq := req
		fuzzedReq.Method = method
		requests = append(requests, fuzzedReq)
	}

	return requests
}

// Function to generate request parameter wrapping
func generateRequestParameterWrapping(req models.Request) []models.Request {
	parsedURL, _ := url.Parse(req.URL)
	queryParams := parsedURL.Query()
	originalParams := map[string][]string{}
	for key, values := range queryParams {
		originalParams[key] = values
	}

	// Generate different wrapping styles dynamically
	wrappingStyles := []string{
		"wrapped",
		"nested",
		"outerWrap",
		"random_" + randomString(5),
		"timeWrap_" + strconv.Itoa(int(time.Now().Unix())),
	}

	for _, style := range wrappingStyles {
		for key, values := range originalParams {
			for _, value := range values {
				queryParams.Add(style+"["+key+"]", value)
			}
		}
	}

	parsedURL.RawQuery = queryParams.Encode()
	req.URL = parsedURL.String()
	return []models.Request{req}
}

// Function to generate body parameter wrapping
func generateBodyParameterWrapping(req models.Request) []models.Request {
	req.Method = "POST"

	bodyParams := parseBodyToParams_(req.Body)

	wrappingStyles := []string{
		"wrapped",
		"nested",
		"outerWrap",
		"random_" + randomString(5),
		"timeWrap_" + strconv.Itoa(int(time.Now().Unix())),
	}

	var wrappedBodies []string

	for _, style := range wrappingStyles {
		wrappedBody := make(map[string]interface{})
		nestedBody := make(map[string]string)

		for key, value := range bodyParams {
			nestedBody[key] = value
		}

		wrappedBody[style] = nestedBody

		jsonBody, _ := json.Marshal(wrappedBody)
		wrappedBodies = append(wrappedBodies, string(jsonBody))
	}

	// Generate one request for each wrapped body
	var wrappedRequests []models.Request
	for _, wrappedBody := range wrappedBodies {
		wrappedReq := req
		wrappedReq.Body = wrappedBody
		wrappedRequests = append(wrappedRequests, wrappedReq)
	}

	return wrappedRequests
}

// Utility to parse query string body into a map
func parseBodyToParams_(body string) map[string]string {
	params := make(map[string]string)
	for _, pair := range strings.Split(body, "&") {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}
	return params
}

// Function to generate requests with substituted body parameters as query parameters
func generateRequestParameterSubstitution(req models.Request) []models.Request {
	var substitutedRequests []models.Request

	parsedParams := parseBodyToParams(req.Body)
	queryParams := url.Values{}
	for key, values := range parsedParams {
		for _, value := range values {
			queryParams.Add(key, value)
		}
	}

	// Update the request URL to include the query parameters
	parsedURL, _ := url.Parse(req.URL)
	parsedURL.RawQuery = queryParams.Encode()

	substitutedReq := req
	substitutedReq.Method = "GET" // Typically, RPS tests convert the method to GET
	substitutedReq.URL = parsedURL.String()
	substitutedReq.Body = "" // Clear the body since parameters are now in the URL
	substitutedRequests = append(substitutedRequests, substitutedReq)

	return substitutedRequests
}

// Utility function to parse body into key-value pairs
func parseBodyToParams(body string) map[string][]string {
	params := make(map[string][]string)
	for _, pair := range strings.Split(body, "&") {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			params[kv[0]] = append(params[kv[0]], kv[1])
		}
	}
	return params
}

// Function to generate requests with substituted body parameters as query parameters with pollution
func generateRequestParameterSubstitutionWithPollution(req models.Request) []models.Request {
	var substitutedRequests []models.Request
	parsedParams := parseBodyToParams(req.Body)

	queryParams := url.Values{}
	for key, values := range parsedParams {
		for _, value := range values {
			queryParams.Add(key, value)             // Add original value
			queryParams.Add(key, "polluted_"+value) // Add polluted value
		}
	}

	parsedURL, _ := url.Parse(req.URL)
	parsedURL.RawQuery = queryParams.Encode()

	substitutedReq := req
	substitutedReq.Method = "GET" // Typically, RPS tests convert the method to GET
	substitutedReq.URL = parsedURL.String()
	substitutedReq.Body = "" // Clear the body since parameters are now in the URL
	substitutedRequests = append(substitutedRequests, substitutedReq)

	return substitutedRequests
}

func generateJSONExtensionRequests(req models.Request) []models.Request {
	req.URL += ".json"
	return []models.Request{req}
}

// Main function to generate fuzzed requests
func GenerateFuzzParams(req models.Request) []models.Request {
	fuzzedRequests := []models.Request{}
	// Fuzz body parameters if body exists
	if req.Body != "" {
		if isJSONBody(req.Body) {
			bodyFuzzedRequests := FuzzJSONBodyParams(req, globalSensitiveParams, minIncrement, maxIncrement)
			fuzzedRequests = append(fuzzedRequests, bodyFuzzedRequests...)
		} else {
			bodyFuzzedRequests := FuzzBodyParams(req, globalSensitiveParams, minIncrement, maxIncrement)
			fuzzedRequests = append(fuzzedRequests, bodyFuzzedRequests...)
		}
	}

	return fuzzedRequests
}

func FuzzJSONBodyParams(req models.Request, sensitiveParams []string, minIncrement, maxIncrement int) []models.Request {
	fuzzedRequests := []models.Request{}
	var jsonParams map[string]interface{}

	// Parse the JSON body
	err := json.Unmarshal([]byte(req.Body), &jsonParams)
	if err != nil {
		slog.Error("Failed to parse JSON body", "error", err)
		return fuzzedRequests
	}

	for _, param := range sensitiveParams {
		// Check if the sensitive parameter exists
		if originalValue, exists := jsonParams[param]; exists {
			var fuzzedValues []string

			switch value := originalValue.(type) {
			case string:
				fuzzedValues = generateIDORFuzzValues(value, minIncrement, maxIncrement)
			case float64:
				fuzzedValues = generateIDORFuzzValues(fmt.Sprintf("%d", int(value)), minIncrement, maxIncrement)
			case int:
				fuzzedValues = generateIDORFuzzValues(fmt.Sprintf("%d", value), minIncrement, maxIncrement)
			default:
				slog.Warn("Unsupported type for param", "param", param, "value", originalValue, "type", fmt.Sprintf("%T", originalValue))
				continue // Skip unsupported types
			}

			// Create a new request for each fuzzed value
			for _, fuzzedValue := range fuzzedValues {
				// Copy and modify the JSON params
				fuzzedParams := copyJSONParams(jsonParams)

				// Convert fuzzedValue back to appropriate type
				if _, isFloat := originalValue.(float64); isFloat {
					if intValue, err := strconv.Atoi(fuzzedValue); err == nil {
						fuzzedParams[param] = float64(intValue)
					} else {
						fuzzedParams[param] = fuzzedValue // Fallback if conversion fails
					}
				} else {
					fuzzedParams[param] = fuzzedValue
				}

				// Marshal the modified JSON params back to a string
				fuzzedBody, err := json.Marshal(fuzzedParams)
				if err != nil {
					slog.Error("Failed to marshal fuzzed JSON", "error", err)
					continue
				}

				// Append the new request
				fuzzedRequests = append(fuzzedRequests, models.Request{
					Body:    string(fuzzedBody),
					Method:  req.Method,
					URL:     req.URL,
					Headers: req.Headers,
				})
			}
		}
	}

	return fuzzedRequests
}

// Function to check if a body is JSON
func isJSONBody(body string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(body), &js) == nil
}

// Helper function to copy a JSON map
func copyJSONParams(original map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})
	for key, value := range original {
		copy[key] = value
	}
	return copy
}

// Function to fuzz form-encoded body parameters (unchanged)
func FuzzBodyParams(req models.Request, sensitiveParams []string, minIncrement, maxIncrement int) []models.Request {
	fuzzedRequests := []models.Request{}
	bodyParams := parseBodyParams(req.Body)

	for _, param := range sensitiveParams {
		if originalValue, exists := bodyParams[param]; exists {
			fuzzedValues := generateIDORFuzzValues(originalValue, minIncrement, maxIncrement)
			for _, fuzzedValue := range fuzzedValues {
				fuzzedParams := copyParams(bodyParams)
				fuzzedParams[param] = fuzzedValue
				fuzzedRequests = append(fuzzedRequests, models.Request{
					Body:    buildBodyFromParams(fuzzedParams),
					Method:  req.Method,
					URL:     req.URL,
					Headers: req.Headers,
				})
			}
		}
	}

	return fuzzedRequests
}

// Helper function to generate fuzzed values
func generateIDORFuzzValues(originalValue string, minIncrement, maxIncrement int) []string {
	fuzzedValues := []string{}
	originalInt, err := strconv.Atoi(originalValue)
	if err != nil {
		return fuzzedValues // Return empty if not a number
	}

	for i := minIncrement; i <= maxIncrement; i++ {
		fuzzedValues = append(fuzzedValues, strconv.Itoa(originalInt+i))
	}

	// Add some additional edge case values
	edgeCases := []string{"0", "-1", strconv.Itoa(originalInt * 2), strconv.Itoa(originalInt / 2)}
	fuzzedValues = append(fuzzedValues, edgeCases...)

	return fuzzedValues
}

// Helper function to parse the body into a map
func parseBodyParams(body string) map[string]string {
	params := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}
	return params
}

// Helper function to build a body string from a map
func buildBodyFromParams(params map[string]string) string {
	var parts []string
	for key, value := range params {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, "&")
}

// Helper function to copy a map
func copyParams(original map[string]string) map[string]string {
	copy := make(map[string]string)
	for key, value := range original {
		copy[key] = value
	}
	return copy
}

func _sendRequest(req models.Request, ws *websocket.Pool, db *gorm.DB) (int, error) {

	// Parse the raw headers string into a map
	parsedHeaders := make(map[string]string)
	lines := strings.Split(req.Headers, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			parsedHeaders[key] = value
		}
	}

	// Create an HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer([]byte(req.Body)))
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set request headers
	for key, value := range parsedHeaders {
		httpReq.Header.Set(key, value)
		//slog.Info(fmt.Sprintf("%s: %s", key, value)) // Log each key-value pair
	}

	slog.Info("Final HTTP Request", "method", httpReq.Method, "url", httpReq.URL.String(), "headers", httpReq.Header, "body", req.Body)

	// Initialize HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Early return if the response status is not successful
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return resp.StatusCode, nil
	}

	// Extract response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	// Log parsed response headers and body
	slog.Info("Response Status", "status", resp.StatusCode)
	slog.Info("Response Body", "body", string(responseBody))

	// Create an AttackResultMessage to broadcast via WebSocket
	if ws != nil {
		m := &types.AttackResultMessage{
			Type:      types.MessageTypeAttackResult,
			Hostname:  httpReq.URL.Hostname(),
			Port:      httpReq.URL.Port(),
			Scheme:    httpReq.URL.Scheme,
			URL:       httpReq.URL.String(),
			Endpoint:  httpReq.URL.Path,
			Request:   "saved in db",
			Response:  "saved in db",
			IpAddress: "",
			Timestamp: time.Now(),
		}
		ws.Broadcast <- m
	}

	// Create a FuzzResult and save it to the database
	if db != nil {
		fuzzResult := &models.FuzzResult{
			Hostname:  httpReq.URL.Hostname(),
			IpAddress: "",
			Port:      httpReq.URL.Port(),
			Scheme:    httpReq.URL.Scheme,
			URL:       httpReq.URL.String(),
			Endpoint:  httpReq.URL.Path,
			Request:   fmt.Sprintf("Headers: %v\nBody: %s", parsedHeaders, req.Body),
			Response:  string(responseBody),
		}
		res := db.Create(fuzzResult)
		if res.Error != nil {
			slog.Error("Failed to save fuzz result", "error", res.Error)
		}
	}

	return resp.StatusCode, nil
}
