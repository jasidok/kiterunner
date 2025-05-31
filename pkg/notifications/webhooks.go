package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/assetnote/kiterunner/pkg/log"
	"github.com/assetnote/kiterunner/pkg/scoring"
)

// NotificationLevel determines what findings trigger notifications
type NotificationLevel int

const (
	NotifyAll NotificationLevel = iota
	NotifyMediumAndAbove
	NotifyHighAndAbove
	NotifyCriticalOnly
)

// NotificationChannel represents different notification channels
type NotificationChannel int

const (
	ChannelWebhook NotificationChannel = iota
	ChannelSlack
	ChannelDiscord
	ChannelEmail
	ChannelCustom
)

// NotificationConfig holds configuration for notifications
type NotificationConfig struct {
	Enabled          bool              `json:"enabled"`
	Level            NotificationLevel `json:"level"`
	Channels         []ChannelConfig   `json:"channels"`
	RateLimitSeconds int               `json:"rate_limit_seconds"`
	MaxNotifications int               `json:"max_notifications"`
	BountyContext    BountyContext     `json:"bounty_context"`
}

// ChannelConfig represents configuration for a notification channel
type ChannelConfig struct {
	Type     NotificationChannel `json:"type"`
	URL      string              `json:"url"`
	Token    string              `json:"token,omitempty"`
	Username string              `json:"username,omitempty"`
	Channel  string              `json:"channel,omitempty"`
	Email    EmailConfig         `json:"email,omitempty"`
	Headers  map[string]string   `json:"headers,omitempty"`
}

// EmailConfig holds email notification configuration
type EmailConfig struct {
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	UseStartTLS bool     `json:"use_starttls"`
}

// BountyContext provides context for bug bounty submissions
type BountyContext struct {
	Program    string   `json:"program"`
	Platform   string   `json:"platform"`
	Scope      string   `json:"scope"`
	Researcher string   `json:"researcher"`
	Session    string   `json:"session"`
	Tags       []string `json:"tags"`
}

// FindingNotification represents a notification about a finding
type FindingNotification struct {
	ID                 string                           `json:"id"`
	Type               string                           `json:"type"`
	Severity           string                           `json:"severity"`
	Title              string                           `json:"title"`
	Description        string                           `json:"description"`
	Endpoint           string                           `json:"endpoint"`
	Method             string                           `json:"method"`
	Evidence           []string                         `json:"evidence"`
	Risk               *scoring.EndpointRisk            `json:"risk,omitempty"`
	Vulnerability      *scoring.VulnerabilityAssessment `json:"vulnerability,omitempty"`
	BountyContext      BountyContext                    `json:"bounty_context"`
	Timestamp          time.Time                        `json:"timestamp"`
	ReadyForSubmission bool                             `json:"ready_for_submission"`
	SubmissionTemplate string                           `json:"submission_template,omitempty"`
}

// SlackPayload represents a Slack webhook payload
type SlackPayload struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackAttachment represents a Slack attachment
type SlackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	TitleLink string       `json:"title_link,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Footer    string       `json:"footer,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

// SlackField represents a Slack field
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// DiscordPayload represents a Discord webhook payload
type DiscordPayload struct {
	Content   string         `json:"content,omitempty"`
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

// DiscordEmbed represents a Discord embed
type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	URL         string              `json:"url,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      DiscordEmbedFooter  `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

// DiscordEmbedField represents a Discord embed field
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// DiscordEmbedFooter represents a Discord embed footer
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// Notifier handles sending notifications
type Notifier struct {
	config       NotificationConfig
	httpClient   *http.Client
	lastNotified time.Time
	notifyCount  int
}

// NewNotifier creates a new notifier instance
func NewNotifier(config NotificationConfig) *Notifier {
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ShouldNotify determines if a finding should trigger a notification
func (n *Notifier) ShouldNotify(riskLevel scoring.RiskLevel) bool {
	if !n.config.Enabled {
		return false
	}

	// Rate limiting
	if n.config.RateLimitSeconds > 0 {
		if time.Since(n.lastNotified) < time.Duration(n.config.RateLimitSeconds)*time.Second {
			return false
		}
	}

	// Max notifications check
	if n.config.MaxNotifications > 0 && n.notifyCount >= n.config.MaxNotifications {
		return false
	}

	// Level check
	switch n.config.Level {
	case NotifyAll:
		return true
	case NotifyMediumAndAbove:
		return riskLevel >= scoring.RiskMedium
	case NotifyHighAndAbove:
		return riskLevel >= scoring.RiskHigh
	case NotifyCriticalOnly:
		return riskLevel == scoring.RiskCritical
	default:
		return false
	}
}

// NotifyEndpointRisk sends notification for endpoint risk finding
func (n *Notifier) NotifyEndpointRisk(risk *scoring.EndpointRisk) error {
	if !n.ShouldNotify(risk.RiskLevel) {
		return nil
	}

	notification := &FindingNotification{
		ID:                 generateID(),
		Type:               "endpoint_risk",
		Severity:           risk.RiskLevel.String(),
		Title:              fmt.Sprintf("High-Risk Endpoint Discovered: %s", risk.Endpoint),
		Description:        fmt.Sprintf("Endpoint %s (%s) has been assessed as %s risk", risk.Endpoint, risk.Method, risk.RiskLevel.String()),
		Endpoint:           risk.Endpoint,
		Method:             risk.Method,
		Evidence:           risk.SensitivityFactors,
		Risk:               risk,
		BountyContext:      n.config.BountyContext,
		Timestamp:          time.Now(),
		ReadyForSubmission: risk.RiskLevel >= scoring.RiskMedium,
	}

	if notification.ReadyForSubmission {
		notification.SubmissionTemplate = n.generateEndpointRiskTemplate(risk)
	}

	return n.sendNotification(notification)
}

// NotifyVulnerability sends notification for vulnerability finding
func (n *Notifier) NotifyVulnerability(vuln *scoring.VulnerabilityAssessment) error {
	if !n.ShouldNotify(vuln.RiskLevel) {
		return nil
	}

	notification := &FindingNotification{
		ID:                 generateID(),
		Type:               "vulnerability",
		Severity:           vuln.RiskLevel.String(),
		Title:              fmt.Sprintf("🚨 %s Vulnerability Found: %s", vuln.RiskLevel.String(), vuln.VulnerabilityType.String()),
		Description:        fmt.Sprintf("%s vulnerability discovered on %s (%s)", vuln.VulnerabilityType.String(), vuln.Endpoint, vuln.Method),
		Endpoint:           vuln.Endpoint,
		Method:             vuln.Method,
		Evidence:           vuln.Evidence,
		Vulnerability:      vuln,
		BountyContext:      n.config.BountyContext,
		Timestamp:          time.Now(),
		ReadyForSubmission: true,
	}

	notification.SubmissionTemplate = n.generateVulnerabilityTemplate(vuln)

	return n.sendNotification(notification)
}

// sendNotification sends notification to all configured channels
func (n *Notifier) sendNotification(notification *FindingNotification) error {
	n.lastNotified = time.Now()
	n.notifyCount++

	var lastError error
	for _, channel := range n.config.Channels {
		if err := n.sendToChannel(notification, channel); err != nil {
			log.Error().Err(err).Str("channel", fmt.Sprintf("%d", channel.Type)).Msg("Failed to send notification")
			lastError = err
		}
	}

	return lastError
}

// sendToChannel sends notification to a specific channel
func (n *Notifier) sendToChannel(notification *FindingNotification, channel ChannelConfig) error {
	switch channel.Type {
	case ChannelWebhook:
		return n.sendWebhook(notification, channel)
	case ChannelSlack:
		return n.sendSlack(notification, channel)
	case ChannelDiscord:
		return n.sendDiscord(notification, channel)
	case ChannelEmail:
		return n.sendEmail(notification, channel)
	case ChannelCustom:
		return n.sendCustom(notification, channel)
	default:
		return fmt.Errorf("unsupported channel type: %d", channel.Type)
	}
}

// sendWebhook sends generic webhook notification
func (n *Notifier) sendWebhook(notification *FindingNotification, channel ChannelConfig) error {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	req, err := http.NewRequest("POST", channel.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiterunner-Godmode/1.0")

	// Add custom headers
	for key, value := range channel.Headers {
		req.Header.Set(key, value)
	}

	// Add authorization if token provided
	if channel.Token != "" {
		req.Header.Set("Authorization", "Bearer "+channel.Token)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendSlack sends Slack notification
func (n *Notifier) sendSlack(notification *FindingNotification, channel ChannelConfig) error {
	color := n.getSeverityColor(notification.Severity)

	payload := SlackPayload{
		Username:  "Kiterunner Godmode",
		Channel:   channel.Channel,
		IconEmoji: ":warning:",
		Attachments: []SlackAttachment{
			{
				Color: color,
				Title: notification.Title,
				Text:  notification.Description,
				Fields: []SlackField{
					{Title: "Endpoint", Value: notification.Endpoint, Short: true},
					{Title: "Method", Value: notification.Method, Short: true},
					{Title: "Severity", Value: notification.Severity, Short: true},
					{Title: "Program", Value: notification.BountyContext.Program, Short: true},
				},
				Footer:    "Kiterunner Godmode Bug Bounty Hunter",
				Timestamp: notification.Timestamp.Unix(),
			},
		},
	}

	// Add submission template if ready
	if notification.ReadyForSubmission && notification.SubmissionTemplate != "" {
		payload.Attachments = append(payload.Attachments, SlackAttachment{
			Color: "good",
			Title: "Ready for Bug Bounty Submission",
			Text:  "```" + notification.SubmissionTemplate + "```",
		})
	}

	return n.sendJSONPayload(payload, channel.URL)
}

// sendDiscord sends Discord notification
func (n *Notifier) sendDiscord(notification *FindingNotification, channel ChannelConfig) error {
	color := n.getDiscordColor(notification.Severity)

	embed := DiscordEmbed{
		Title:       notification.Title,
		Description: notification.Description,
		Color:       color,
		Fields: []DiscordEmbedField{
			{Name: "Endpoint", Value: notification.Endpoint, Inline: true},
			{Name: "Method", Value: notification.Method, Inline: true},
			{Name: "Severity", Value: notification.Severity, Inline: true},
			{Name: "Program", Value: notification.BountyContext.Program, Inline: true},
		},
		Footer:    DiscordEmbedFooter{Text: "Kiterunner Godmode Bug Bounty Hunter"},
		Timestamp: notification.Timestamp.Format(time.RFC3339),
	}

	// Add evidence if available
	if len(notification.Evidence) > 0 {
		evidenceText := strings.Join(notification.Evidence, ", ")
		embed.Fields = append(embed.Fields, DiscordEmbedField{
			Name:   "Evidence",
			Value:  evidenceText,
			Inline: false,
		})
	}

	payload := DiscordPayload{
		Username:  "Kiterunner Godmode",
		AvatarURL: "https://example.com/kiterunner-avatar.png",
		Embeds:    []DiscordEmbed{embed},
	}

	// Add submission template if ready
	if notification.ReadyForSubmission && notification.SubmissionTemplate != "" {
		payload.Content = "🎯 **Ready for Bug Bounty Submission!**\n```\n" + notification.SubmissionTemplate + "\n```"
	}

	return n.sendJSONPayload(payload, channel.URL)
}

// sendEmail sends email notification
func (n *Notifier) sendEmail(notification *FindingNotification, channel ChannelConfig) error {
	auth := smtp.PlainAuth("", channel.Email.Username, channel.Email.Password, channel.Email.SMTPHost)

	subject := channel.Email.Subject
	if subject == "" {
		subject = fmt.Sprintf("Kiterunner Alert: %s", notification.Title)
	}

	body := n.generateEmailBody(notification)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		channel.Email.From,
		strings.Join(channel.Email.To, ","),
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%d", channel.Email.SMTPHost, channel.Email.SMTPPort)
	return smtp.SendMail(addr, auth, channel.Email.From, channel.Email.To, []byte(msg))
}

// sendCustom sends custom webhook with specific formatting
func (n *Notifier) sendCustom(notification *FindingNotification, channel ChannelConfig) error {
	// Custom payload can be implemented based on specific requirements
	return n.sendWebhook(notification, channel)
}

// sendJSONPayload sends JSON payload to URL
func (n *Notifier) sendJSONPayload(payload interface{}, url string) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := n.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("payload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// generateEndpointRiskTemplate generates bug bounty submission template for endpoint risk
func (n *Notifier) generateEndpointRiskTemplate(risk *scoring.EndpointRisk) string {
	template := fmt.Sprintf(`# High-Risk Endpoint Discovery

## Summary
Discovered high-risk endpoint that may be vulnerable to exploitation.

## Details
- **Endpoint**: %s
- **Method**: %s
- **Risk Level**: %s
- **Risk Score**: %d/100
- **Business Impact**: %s
- **Exploitability**: %s
- **Access Level Required**: %s
- **Data Sensitivity**: %s

## Risk Factors
%s

## Recommendation
This endpoint should be reviewed for:
- Proper authentication and authorization controls
- Input validation and sanitization
- Rate limiting and abuse prevention
- Sensitive data exposure

## Timeline
- **Discovered**: %s
- **Program**: %s
- **Researcher**: %s
`,
		risk.Endpoint,
		risk.Method,
		risk.RiskLevel.String(),
		risk.Score,
		risk.BusinessImpact,
		risk.Exploitability,
		risk.AccessLevel,
		risk.DataSensitivity,
		strings.Join(risk.SensitivityFactors, ", "),
		risk.Timestamp.Format("2006-01-02 15:04:05"),
		n.config.BountyContext.Program,
		n.config.BountyContext.Researcher,
	)

	return template
}

// generateVulnerabilityTemplate generates bug bounty submission template for vulnerability
func (n *Notifier) generateVulnerabilityTemplate(vuln *scoring.VulnerabilityAssessment) string {
	template := fmt.Sprintf(`# %s - %s

## Summary
%s

## Vulnerability Details
- **Type**: %s
- **Endpoint**: %s
- **Method**: %s
- **Severity**: %s
- **CVSS Score**: %.1f
- **Risk Score**: %d/100

## Business Impact
%s

## Technical Details
**Evidence:**
%s

**Payload Used:**
%s

**Response:**
%s

## Remediation
%s

## References
%s

## Timeline
- **Discovered**: %s
- **Program**: %s
- **Researcher**: %s

## Proof of Concept
[Add PoC steps here]

## Impact Assessment
This vulnerability could lead to significant security issues including potential data exposure, unauthorized access, or system compromise.
`,
		vuln.VulnerabilityType.String(),
		vuln.RiskLevel.String(),
		vuln.BusinessImpact,
		vuln.VulnerabilityType.String(),
		vuln.Endpoint,
		vuln.Method,
		vuln.RiskLevel.String(),
		vuln.CVSS,
		vuln.Score,
		vuln.BusinessImpact,
		strings.Join(vuln.Evidence, "\n"),
		vuln.Payload,
		vuln.Response,
		vuln.Remediation,
		strings.Join(vuln.References, "\n"),
		vuln.Timestamp.Format("2006-01-02 15:04:05"),
		n.config.BountyContext.Program,
		n.config.BountyContext.Researcher,
	)

	return template
}

// generateEmailBody generates email body for notification
func (n *Notifier) generateEmailBody(notification *FindingNotification) string {
	body := fmt.Sprintf(`Kiterunner Godmode Alert

%s

Endpoint: %s
Method: %s
Severity: %s
Program: %s
Time: %s

%s

---
This alert was generated by Kiterunner Godmode
Session: %s
`,
		notification.Title,
		notification.Endpoint,
		notification.Method,
		notification.Severity,
		notification.BountyContext.Program,
		notification.Timestamp.Format("2006-01-02 15:04:05"),
		notification.Description,
		notification.BountyContext.Session,
	)

	if notification.ReadyForSubmission && notification.SubmissionTemplate != "" {
		body += "\n\nBug Bounty Submission Template:\n" + notification.SubmissionTemplate
	}

	return body
}

// getSeverityColor returns Slack color for severity
func (n *Notifier) getSeverityColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "danger"
	case "HIGH":
		return "warning"
	case "MEDIUM":
		return "#ffcc00"
	case "LOW":
		return "good"
	default:
		return "#cccccc"
	}
}

// getDiscordColor returns Discord color for severity
func (n *Notifier) getDiscordColor(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0xFF0000 // Red
	case "HIGH":
		return 0xFF6600 // Orange
	case "MEDIUM":
		return 0xFFCC00 // Yellow
	case "LOW":
		return 0x00FF00 // Green
	default:
		return 0xCCCCCC // Gray
	}
}

// generateID generates a simple ID for notifications
func generateID() string {
	return fmt.Sprintf("kr-%d", time.Now().UnixNano())
}
