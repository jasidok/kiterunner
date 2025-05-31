# 🚀 Kiterunner Configuration Files

This directory contains optimized configuration files for different use cases of the enhanced Kiterunner tool.

## 📁 Available Configurations

### 1. `.kiterunner.yaml` - Default Configuration

**The main configuration file with all features documented**

- Balanced settings for general use
- All options explained with comments
- Preset configurations included (commented)
- Place at: `$HOME/.kiterunner.yaml`

### 2. `.kiterunner-aggressive.yaml` - Bug Bounty Mode 🚀

**Maximum performance for bug bounty hunting**

- High concurrency (25 connections per host, 300 parallel hosts)
- All AI features enabled
- Advanced reporting (HTML, Burp, Nuclei templates)
- Real-time notifications
- Large wordlists (50K+ routes)

### 3. `.kiterunner-stealth.yaml` - Stealth Mode 👻

**Maximum evasion for sensitive targets**

- Ultra-low profile (2 connections, 5 hosts)
- Long delays (1-5 seconds between requests)
- Realistic browser headers
- Minimal logging
- Small wordlists to avoid detection

### 4. `.kiterunner-enterprise.yaml` - Enterprise Mode 🏢

**Professional pentesting and security assessments**

- Balanced performance and stealth
- Comprehensive reporting (SARIF, HTML, Burp)
- Full coverage testing
- Professional documentation
- Enterprise-grade features

## 🎯 How to Use

### Option 1: Default Configuration

```bash
# Copy to home directory
cp .kiterunner.yaml $HOME/

# Use automatically
kiterunner scan target.com -w wordlist.kite
```

### Option 2: Specific Configuration

```bash
# Use specific config file
kiterunner scan target.com -w wordlist.kite --config .kiterunner-aggressive.yaml
```

### Option 3: Override Specific Settings

```bash
# Use config but override specific settings
kiterunner scan target.com -w wordlist.kite --max-connection-per-host 5
```

## 🔧 Quick Start Examples

### Bug Bounty Hunting

```bash
kiterunner scan targets.txt \
  --config .kiterunner-aggressive.yaml \
  -A apiroutes-240528:50000 \
  --enable-all-ai-features \
  --html-report report.html
```

### Stealth Reconnaissance

```bash
kiterunner scan target.com \
  --config .kiterunner-stealth.yaml \
  --stealth-proxy socks5://127.0.0.1:9050 \
  -A raft-small-words:1000
```

### Enterprise Assessment

```bash
kiterunner scan enterprise-targets.txt \
  --config .kiterunner-enterprise.yaml \
  --enable-advanced-output \
  --sarif-output security-report.sarif
```

## ⚙️ Customization Tips

### 1. Webhook Notifications

```yaml
# Add to any config file
slack-webhook: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
discord-webhook: "https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK"
enable-notifications: true
notification-level: "high"
```

### 2. Proxy Settings

```yaml
# For stealth or corporate environments
stealth-proxy: "http://proxy.company.com:8080"
# or
stealth-proxy: "socks5://127.0.0.1:9050"  # Tor
```

### 3. Custom Wordlists

```yaml
# Add custom Assetnote wordlists
assetnote-wordlists:
  - "your-custom-wordlist:10000"
  - "apiroutes-240528:25000"
  - "parameters-240528:5000"
```

### 4. Output Formats

```yaml
# Enable multiple output formats 
output-formats: ["json", "csv", "html", "burp", "nuclei", "sarif"]
output-dir: "./results"
```

## 🎛️ Performance Tuning

### High Performance (Bug Bounty)

- `max-connection-per-host: 20-30`
- `max-parallel-hosts: 200-500`
- `performance-mode: "aggressive"`
- `adaptive-concurrency: true`

### Stealth Mode

- `max-connection-per-host: 1-3`
- `max-parallel-hosts: 5-10`
- `stealth-delay-min: 1000-5000`
- `performance-mode: "conservative"`

### Balanced (Enterprise)

- `max-connection-per-host: 10-15`
- `max-parallel-hosts: 50-150`
- `performance-mode: "balanced"`
- `stealth-mode: "ninja"`

## 📊 Feature Matrix

| Feature | Default | Aggressive | Stealth | Enterprise |
|---------|---------|------------|---------|------------|
| AI Features | Selective | All | Minimal | Professional |
| Performance | Balanced | Maximum | Minimal | Balanced |
| Stealth | Ninja | Fast | Ghost | Ninja |
| Reporting | Basic | Advanced | Minimal | Comprehensive |
| Notifications | Optional | Enabled | Disabled | Enabled |

## 🔒 Security Notes

- **Never commit** config files with real webhook URLs or credentials
- Use **environment variables** for sensitive data
- Test configurations on **non-production** targets first
- Monitor **resource usage** during scans
- Respect **rate limits** and **robots.txt**

## 🚀 Next Steps

1. Choose the appropriate configuration for your use case
2. Customize webhook URLs and researcher information
3. Test on a controlled target
4. Scale up gradually
5. Monitor results and adjust as needed

Happy hunting! 🎯