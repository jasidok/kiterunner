#!/bin/bash

# 🚀 Kiterunner Configuration Setup Script
# Sets up default configuration file for enhanced Kiterunner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print header
echo -e "${PURPLE}"
echo "██╗  ██╗██╗████████╗███████╗██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗ "
echo "██║ ██╔╝██║╚══██╔══╝██╔════╝██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗"
echo "█████╔╝ ██║   ██║   █████╗  ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝"
echo "██╔═██╗ ██║   ██║   ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗"
echo "██║  ██╗██║   ██║   ███████╗██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║"
echo "╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${CYAN}🚀 KITERUNNER GODMODE CONFIGURATION SETUP${NC}"
echo -e "${YELLOW}Enhanced with 5-Phase Implementation - Bug Bounty Money-Printing Machine${NC}"
echo ""

# Check if config directory exists
CONFIG_DIR="$HOME"
CONFIG_FILE="$HOME/.kiterunner.yaml"

echo -e "${BLUE}📁 Configuration Setup${NC}"
echo "   Target: $CONFIG_FILE"
echo ""

# Check if config already exists
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}⚠️  Configuration file already exists!${NC}"
    echo -e "   Current file: $CONFIG_FILE"
    echo ""
    read -p "   Do you want to backup and replace it? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup existing config
        BACKUP_FILE="$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${YELLOW}💾 Backing up existing config to: $BACKUP_FILE${NC}"
        cp "$CONFIG_FILE" "$BACKUP_FILE"
    else
        echo -e "${RED}❌ Setup cancelled by user${NC}"
        exit 1
    fi
fi

# Copy default config
echo -e "${BLUE}📋 Installing default configuration...${NC}"
if [ -f ".kiterunner.yaml" ]; then
    cp ".kiterunner.yaml" "$CONFIG_FILE"
    echo -e "${GREEN}✅ Default configuration installed successfully!${NC}"
else
    echo -e "${RED}❌ Error: .kiterunner.yaml not found in current directory${NC}"
    echo -e "   Please run this script from the kiterunner directory"
    exit 1
fi

# Show available configurations
echo ""
echo -e "${PURPLE}📁 Available Configuration Files:${NC}"
echo ""

if [ -f ".kiterunner-aggressive.yaml" ]; then
    echo -e "${GREEN}🚀 .kiterunner-aggressive.yaml${NC} - Bug Bounty Mode"
    echo -e "   ${CYAN}High performance, all AI features, maximum detection${NC}"
fi

if [ -f ".kiterunner-stealth.yaml" ]; then
    echo -e "${GREEN}👻 .kiterunner-stealth.yaml${NC} - Stealth Mode"
    echo -e "   ${CYAN}Maximum evasion, minimal footprint, ghost mode${NC}"
fi

if [ -f ".kiterunner-enterprise.yaml" ]; then
    echo -e "${GREEN}🏢 .kiterunner-enterprise.yaml${NC} - Enterprise Mode"
    echo -e "   ${CYAN}Professional pentesting, comprehensive reporting${NC}"
fi

echo ""
echo -e "${BLUE}🎯 Quick Start Examples:${NC}"
echo ""
echo -e "${YELLOW}Default Configuration:${NC}"
echo "   kiterunner scan target.com -w wordlist.kite"
echo ""
echo -e "${YELLOW}Bug Bounty Mode:${NC}"
echo "   kiterunner scan targets.txt --config .kiterunner-aggressive.yaml"
echo ""
echo -e "${YELLOW}Stealth Mode:${NC}"
echo "   kiterunner scan target.com --config .kiterunner-stealth.yaml"
echo ""
echo -e "${YELLOW}Enterprise Mode:${NC}"
echo "   kiterunner scan targets.txt --config .kiterunner-enterprise.yaml"
echo ""

# Customization tips
echo -e "${PURPLE}⚙️  Customization Tips:${NC}"
echo ""
echo -e "${CYAN}1. Edit your config:${NC} nano $CONFIG_FILE"
echo -e "${CYAN}2. Set researcher name:${NC} Update 'researcher: \"YourName\"'"
echo -e "${CYAN}3. Add webhooks:${NC} Configure Slack/Discord notifications"
echo -e "${CYAN}4. Adjust performance:${NC} Tune concurrency for your hardware"
echo -e "${CYAN}5. Enable AI features:${NC} Set 'enable-all-ai-features: true'"
echo ""

echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo -e "${YELLOW}Your enhanced Kiterunner is ready for bug bounty hunting!${NC}"
echo ""
echo -e "${CYAN}For detailed documentation, see: CONFIG-README.md${NC}"
echo -e "${CYAN}Happy hunting! 🎯${NC}"