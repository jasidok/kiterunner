package cmd

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/pprof"
	"time"

	"github.com/assetnote/kiterunner/internal/scan"
	"github.com/assetnote/kiterunner/pkg/context"
	"github.com/assetnote/kiterunner/pkg/log"
	"github.com/spf13/cobra"
)

var (
	kitebuilderFiles    = []string{}
	kitebuilderFullScan = false
	headers             = []string{}

	failStatusCodes    = []int{}
	successStatusCodes = []int{}
	lengthIgnoreRange  = []string{}

	progressBar               = true
	disablePrecheck           = false
	wildcardDetection         = true
	maxConnPerHost            = 3
	maxParallelHosts          = 50
	delay                     = 0 * time.Second
	userAgent                 = "Chrome. Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"
	quarantineThreshold int64 = 10

	timeout      = 3 * time.Second
	maxRedirects = 3

	preflightDepth   int64 = 1
	blacklistDomains       = []string{}
	filterAPIs             = []string{}

	forceMethod = ""

	profileName = ""

	assetnoteWordlist = []string{}

	// New AI-powered features
	enableParameterDiscovery      = false
	enableVulnerabilityDetection  = false
	enableResponseIntelligence    = false
	enableSmartWordlistGeneration = false
	enableAllAIFeatures           = false

	// Phase 2: Advanced Discovery Features
	enableMultiMethodDiscovery = false
	enableHeaderBasedDiscovery = false
	enableEncodingBypass       = false
	enableAllPhase2Features    = false

	// Phase 4: Intelligence & Reporting Features
	enableRiskScoring       = false
	enableNotifications     = false
	enableAdvancedOutput    = false
	enableAllPhase4Features = false
	outputFormats           = []string{}
	outputDirectory         = "./results"
	notificationConfig      = ""
	burpProjectOutput       = ""
	nucleiTemplateOutput    = ""
	markdownReportOutput    = ""
	htmlReportOutput        = ""
	sarif_output            = ""

	// Risk scoring options
	riskThreshold = "medium"

	// Notification options
	slackWebhook      = ""
	discordWebhook    = ""
	emailConfig       = ""
	webhookURL        = ""
	notificationLevel = "high"
	bountyProgram     = ""
	bountyPlatform    = ""
	researcher        = ""

	// Phase 5: Stealth and Performance Features
	enableStealth       = false
	stealthMode         = ""
	performanceMode     = ""
	adaptiveConcurrency = false
	targetResponseTime  = 500 * time.Millisecond
	enableCache         = false
	maxCacheSize        = 100
	maxMemoryUsage      = 500
	stealthProxy        = ""
	stealthUserAgents   = []string{}
	stealthDelayMin     = 50
	stealthDelayMax     = 200
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan INPUT [ -w wordlist.kite ]",
	Short: "scan one or multiple hosts with a provided wordlist",
	Long: `this will perform a concurrent scan of one or multiple hosts
using a generate kiterunner wordlist.
We will attempt to find a file matching your provided <input>, and otherwise
attempt to parse it as a URI. 
If protocol is missing, then we will assume from the port.
If the port is missing, then we will try both http:80 and https:443

The kitebuilder file format is a modified openAPI schema that allows you to specify
arguments, parameters, headers, methods and body structure for structured api calls.
We can load an kitebuilder file in as the wordlist. 
By default, we perform a 2 phase kitebuilder scan. The first phase uses a single route for api schema.
If any of the routes respond, we perform a second phase scan on the host where all the routes for an api
are scanned

usage: 
kr scan <input> <flags>
kr scan hosts.txt -A=apiroutes-210228:5000 
kr scan domain.com -w wordlist.kite
kr scan domains.txt -W rafter.txt -D=0 # this just uses the words as a normal wordlist, disables depth scanning

`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		opts := []scan.ScanOption{
			scan.MaxParallelHosts(maxParallelHosts),
			scan.MaxConnPerHost(maxConnPerHost),
			scan.MaxRedirects(maxRedirects),
			scan.ContentLengthIgnoreRanges(lengthIgnoreRange),
			scan.Timeout(timeout),
			scan.Delay(delay),
			scan.AddHeaders(headers),
			scan.LoadKitebuilderFile(kitebuilderFiles),
			scan.KitebuilderFullScan(kitebuilderFullScan),
			scan.LoadAssetnoteWordlistKitebuilder(assetnoteWordlist),
			scan.ForceMethod(forceMethod),
			scan.UserAgent(userAgent),
			scan.SuccessStatusCodes(successStatusCodes),
			scan.FailStatusCodes(failStatusCodes),
			scan.BlacklistDomains(blacklistDomains),
			scan.FilterAPIs(filterAPIs),
			scan.WildcardDetection(wildcardDetection),
			scan.ProgressBarEnabled(progressBar),
			scan.QuarantineThreshold(quarantineThreshold),
			scan.PreflightDepth(preflightDepth),
			scan.Precheck(!disablePrecheck),
			scan.EnableParameterDiscovery(enableParameterDiscovery),
			scan.EnableVulnerabilityDetection(enableVulnerabilityDetection),
			scan.EnableResponseIntelligence(enableResponseIntelligence),
			scan.EnableSmartWordlistGeneration(enableSmartWordlistGeneration),
			scan.EnableAllAIFeatures(enableAllAIFeatures),
			scan.EnableMultiMethodDiscovery(enableMultiMethodDiscovery),
			scan.EnableHeaderBasedDiscovery(enableHeaderBasedDiscovery),
			scan.EnableEncodingBypass(enableEncodingBypass),
			scan.EnableAllPhase2Features(enableAllPhase2Features),
			scan.EnableRiskScoring(enableRiskScoring),
			scan.EnableNotifications(enableNotifications),
			scan.EnableAdvancedOutput(enableAdvancedOutput),
			scan.EnableAllPhase4Features(enableAllPhase4Features),
			scan.SetOutputFormats(outputFormats),
			scan.SetOutputDirectory(outputDirectory),
			scan.SetBurpProjectOutput(burpProjectOutput),
			scan.SetNucleiTemplateOutput(nucleiTemplateOutput),
			scan.SetMarkdownReportOutput(markdownReportOutput),
			scan.SetHTMLReportOutput(htmlReportOutput),
			scan.SetSARIFOutput(sarif_output),
			scan.SetRiskThreshold(riskThreshold),
			scan.SetNotificationConfig(notificationConfig),
			scan.SetSlackWebhook(slackWebhook),
			scan.SetDiscordWebhook(discordWebhook),
			scan.SetEmailConfig(emailConfig),
			scan.SetWebhookURL(webhookURL),
			scan.SetNotificationLevel(notificationLevel),
			scan.SetBountyProgram(bountyProgram),
			scan.SetBountyPlatform(bountyPlatform),
			scan.SetResearcher(researcher),

			// Phase 5: Stealth and Performance options
			scan.EnableStealth(enableStealth),
			scan.SetStealthMode(stealthMode),
			scan.SetPerformanceMode(performanceMode),
			scan.EnableAdaptiveConcurrency(adaptiveConcurrency),
			scan.SetTargetResponseTime(targetResponseTime),
			scan.EnableCache(enableCache),
			scan.SetMaxCacheSize(maxCacheSize),
			scan.SetMaxMemoryUsage(maxMemoryUsage),
			scan.SetStealthProxy(stealthProxy),
			scan.SetStealthUserAgents(stealthUserAgents),
			scan.SetStealthDelay(stealthDelayMin, stealthDelayMax),
		}

		go func() {
			log.Debug().Err(http.ListenAndServe("localhost:6060", nil)).Msg("Started http profiler server")
		}()

		if profileName != "" {
			f, err := os.Create(profileName)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to create profile")
			}

			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}

		if domain == "-" {
			if err := scan.ScanStdin(context.Context(), opts...); err != nil {
				log.Fatal().Err(err).Msg("failed to read from stdin")
			}
		} else {
			if err := scan.ScanDomainOrFile(context.Context(), domain, opts...); err != nil {
				log.Fatal().Err(err).Msg("failed to scan domain")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringSliceVarP(&kitebuilderFiles, "kitebuilder-list", "w", kitebuilderFiles, "ogl wordlist to use for scanning")
	scanCmd.Flags().BoolVar(&kitebuilderFullScan, "kitebuilder-full-scan", kitebuilderFullScan, "perform a full scan without first performing a phase scan.")
	scanCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{"x-forwarded-for: 127.0.0.1"}, "headers to add to requests")

	scanCmd.Flags().BoolVar(&disablePrecheck, "disable-precheck", false, "whether to skip host discovery")

	scanCmd.Flags().IntVarP(&maxConnPerHost, "max-connection-per-host", "x", maxConnPerHost, "max connections to a single host")
	scanCmd.Flags().IntVarP(&maxParallelHosts, "max-parallel-hosts", "j", maxParallelHosts, "max number of concurrent hosts to scan at once")
	scanCmd.Flags().DurationVar(&delay, "delay", delay, "delay to place inbetween requests to a single host")
	scanCmd.Flags().StringVar(&userAgent, "user-agent", userAgent, "user agent to use for requests")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", timeout, "timeout to use on all requests")
	scanCmd.Flags().IntVar(&maxRedirects, "max-redirects", maxRedirects, "maximum number of redirects to follow")
	scanCmd.Flags().StringVar(&forceMethod, "force-method", forceMethod, "whether to ignore the methods specified in the ogl file and force this method")

	scanCmd.Flags().IntSliceVar(&successStatusCodes, "success-status-codes", successStatusCodes,
		"which status codes whitelist as success. this is the default mode")
	scanCmd.Flags().IntSliceVar(&failStatusCodes, "fail-status-codes", failStatusCodes,
		"which status codes blacklist as fail. if this is set, this will override success-status-codes")

	scanCmd.Flags().StringSliceVar(&blacklistDomains, "blacklist-domain", blacklistDomains, "domains that are blacklisted for redirects. We will not follow redirects to these domains")
	scanCmd.Flags().BoolVar(&wildcardDetection, "wildcard-detection", wildcardDetection, "can be set to false to disable wildcard redirect detection")
	scanCmd.Flags().StringSliceVar(&lengthIgnoreRange, "ignore-length", lengthIgnoreRange, "a range of content length bytes to ignore. you can have multiple. e.g. 100-105 or 1234 or 123,34-53. This is inclusive on both ends")

	scanCmd.Flags().BoolVar(&progressBar, "progress", progressBar, "a progress bar while scanning. by default enabled only on Stderr")
	scanCmd.Flags().Int64Var(&quarantineThreshold, "quarantine-threshold", quarantineThreshold, "if the host return N consecutive hits, we quarantine the host as wildcard. Set to 0 to disable")

	scanCmd.Flags().Int64VarP(&preflightDepth, "preflight-depth", "d", 1, "when performing preflight checks, what directory depth do we attempt to check. 0 means that only the docroot is checked")
	scanCmd.Flags().StringVar(&profileName, "profile-name", profileName, "name for profile output file")

	scanCmd.Flags().StringSliceVar(&filterAPIs, "filter-api", filterAPIs, "only scan apis matching this ksuid")

	scanCmd.Flags().StringSliceVarP(&assetnoteWordlist, "assetnote-wordlist", "A", assetnoteWordlist, "use the wordlists from wordlist.assetnote.io. specify the type/name to use, e.g. apiroutes-210228. You can specify an additional maxlength to use only the first N values in the wordlist, e.g. apiroutes-210228;20000 will only use the first 20000 lines in that wordlist")

	scanCmd.Flags().BoolVar(&enableParameterDiscovery, "enable-parameter-discovery", enableParameterDiscovery, "enable AI-powered parameter discovery feature")
	scanCmd.Flags().BoolVar(&enableVulnerabilityDetection, "enable-vulnerability-detection", enableVulnerabilityDetection, "enable AI-powered vulnerability detection feature")
	scanCmd.Flags().BoolVar(&enableResponseIntelligence, "enable-response-intelligence", enableResponseIntelligence, "enable AI-powered response intelligence feature")
	scanCmd.Flags().BoolVar(&enableSmartWordlistGeneration, "enable-smart-wordlist-generation", enableSmartWordlistGeneration, "enable AI-powered smart wordlist generation feature")
	scanCmd.Flags().BoolVar(&enableAllAIFeatures, "enable-all-ai-features", enableAllAIFeatures, "enable all AI-powered features")

	scanCmd.Flags().BoolVar(&enableMultiMethodDiscovery, "enable-multi-method-discovery", enableMultiMethodDiscovery, "enable multi-method discovery for advanced endpoint discovery")
	scanCmd.Flags().BoolVar(&enableHeaderBasedDiscovery, "enable-header-based-discovery", enableHeaderBasedDiscovery, "enable header-based discovery for advanced endpoint discovery")
	scanCmd.Flags().BoolVar(&enableEncodingBypass, "enable-encoding-bypass", enableEncodingBypass, "enable encoding bypass techniques for advanced endpoint discovery")
	scanCmd.Flags().BoolVar(&enableAllPhase2Features, "enable-all-phase2-features", enableAllPhase2Features, "enable all Phase 2 advanced discovery features")

	// Phase 4: Intelligence & Reporting flags
	scanCmd.Flags().BoolVar(&enableRiskScoring, "enable-risk-scoring", enableRiskScoring, "enable intelligent risk scoring of discovered endpoints")
	scanCmd.Flags().BoolVar(&enableNotifications, "enable-notifications", enableNotifications, "enable real-time notifications for high-value findings")
	scanCmd.Flags().BoolVar(&enableAdvancedOutput, "enable-advanced-output", enableAdvancedOutput, "enable advanced output formats (Burp, Nuclei, SARIF)")
	scanCmd.Flags().BoolVar(&enableAllPhase4Features, "enable-all-phase4-features", enableAllPhase4Features, "enable all Phase 4 Intelligence & Reporting features")

	// Output format options
	scanCmd.Flags().StringSliceVar(&outputFormats, "output-formats", outputFormats, "output formats (json,xml,burp,nuclei,markdown,html,csv,sarif)")
	scanCmd.Flags().StringVar(&outputDirectory, "output-dir", outputDirectory, "directory for output files")
	scanCmd.Flags().StringVar(&burpProjectOutput, "burp-output", burpProjectOutput, "export findings as Burp Suite project file")
	scanCmd.Flags().StringVar(&nucleiTemplateOutput, "nuclei-output", nucleiTemplateOutput, "generate Nuclei templates for high-risk findings")
	scanCmd.Flags().StringVar(&markdownReportOutput, "markdown-report", markdownReportOutput, "generate markdown bug bounty report")
	scanCmd.Flags().StringVar(&htmlReportOutput, "html-report", htmlReportOutput, "generate HTML vulnerability report")
	scanCmd.Flags().StringVar(&sarif_output, "sarif-output", sarif_output, "export results in SARIF format for CI/CD integration")

	// Risk scoring options
	scanCmd.Flags().StringVar(&riskThreshold, "risk-threshold", riskThreshold, "minimum risk level to report (low,medium,high,critical)")

	// Notification options
	scanCmd.Flags().StringVar(&notificationConfig, "notification-config", notificationConfig, "JSON config file for notifications")
	scanCmd.Flags().StringVar(&slackWebhook, "slack-webhook", slackWebhook, "Slack webhook URL for real-time alerts")
	scanCmd.Flags().StringVar(&discordWebhook, "discord-webhook", discordWebhook, "Discord webhook URL for real-time alerts")
	scanCmd.Flags().StringVar(&emailConfig, "email-config", emailConfig, "email configuration for alerts (smtp_host:port:username:password:from:to)")
	scanCmd.Flags().StringVar(&webhookURL, "webhook-url", webhookURL, "generic webhook URL for custom integrations")
	scanCmd.Flags().StringVar(&notificationLevel, "notification-level", notificationLevel, "notification threshold (all,medium,high,critical)")

	// Bug bounty context
	scanCmd.Flags().StringVar(&bountyProgram, "bounty-program", bountyProgram, "bug bounty program name for reports")
	scanCmd.Flags().StringVar(&bountyPlatform, "bounty-platform", bountyPlatform, "bug bounty platform (hackerone,bugcrowd,etc)")
	scanCmd.Flags().StringVar(&researcher, "researcher", researcher, "researcher name for bug bounty submissions")

	// Phase 5: Stealth and Performance Features
	scanCmd.Flags().BoolVar(&enableStealth, "enable-stealth", enableStealth, "enable stealth mode for evasion")
	scanCmd.Flags().StringVar(&stealthMode, "stealth-mode", stealthMode, "stealth preset: ghost (max stealth), ninja (balanced), fast (minimal)")
	scanCmd.Flags().StringVar(&performanceMode, "performance-mode", performanceMode, "performance preset: aggressive, balanced, conservative")
	scanCmd.Flags().BoolVar(&adaptiveConcurrency, "adaptive-concurrency", adaptiveConcurrency, "enable adaptive concurrency based on target response")
	scanCmd.Flags().DurationVar(&targetResponseTime, "target-response-time", targetResponseTime, "target response time for adaptive concurrency")
	scanCmd.Flags().BoolVar(&enableCache, "enable-cache", enableCache, "enable smart response caching")
	scanCmd.Flags().IntVar(&maxCacheSize, "max-cache-size", maxCacheSize, "maximum cache size in MB")
	scanCmd.Flags().IntVar(&maxMemoryUsage, "max-memory", maxMemoryUsage, "maximum memory usage in MB")
	scanCmd.Flags().StringVar(&stealthProxy, "stealth-proxy", stealthProxy, "proxy URL for stealth requests (http/https/socks5)")
	scanCmd.Flags().StringSliceVar(&stealthUserAgents, "stealth-user-agents", stealthUserAgents, "custom user agents for stealth mode")
	scanCmd.Flags().IntVar(&stealthDelayMin, "stealth-delay-min", stealthDelayMin, "minimum delay between requests in ms")
	scanCmd.Flags().IntVar(&stealthDelayMax, "stealth-delay-max", stealthDelayMax, "maximum delay between requests in ms")
}
