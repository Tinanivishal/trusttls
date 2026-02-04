package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type UI struct {
	verbose bool
	colors  bool
	reader  *bufio.Reader
}

func NewUI(verbose bool) *UI {
	return &UI{
		verbose: verbose,
		colors:  isTerminal(),
		reader:  bufio.NewReader(os.Stdin),
	}
}

func (ui *UI) PrintHeader(title string) {
	border := strings.Repeat("═", len(title)+4)
	if ui.colors {
		fmt.Printf("\n\033[1;36m%s\033[0m\n", border)
		fmt.Printf("\033[1;36m║ %s ║\033[0m\n", title)
		fmt.Printf("\033[1;36m%s\033[0m\n\n", border)
	} else {
		fmt.Printf("\n%s\n║ %s ║\n%s\n\n", border, title, border)
	}
}

func (ui *UI) PrintStep(current, total int, description string) {
	step := fmt.Sprintf("Step %d/%d", current, total)
	if ui.colors {
		fmt.Printf("\033[1;33m🔧 %s\033[0m \033[1m%s\033[0m\n", step, description)
	} else {
		fmt.Printf("🔧 %s %s\n", step, description)
	}
}

func (ui *UI) PrintSuccess(message string) {
	if ui.colors {
		fmt.Printf("\033[1;32m✅ Success:\033[0m %s\n", message)
	} else {
		fmt.Printf("✅ Success: %s\n", message)
	}
}

func (ui *UI) PrintInfo(message string) {
	if ui.colors {
		fmt.Printf("\033[1;34mℹ️  Info:\033[0m %s\n", message)
	} else {
		fmt.Printf("ℹ️  Info: %s\n", message)
	}
}

func (ui *UI) PrintWarning(message string) {
	if ui.colors {
		fmt.Printf("\033[1;33m⚠️  Warning:\033[0m %s\n", message)
	} else {
		fmt.Printf("⚠️  Warning: %s\n", message)
	}
}

func (ui *UI) PrintError(message string) {
	if ui.colors {
		fmt.Printf("\033[1;31m❌ Error:\033[0m %s\n", message)
	} else {
		fmt.Printf("❌ Error: %s\n", message)
	}
}

func (ui *UI) PrintProgress(message string) {
	if ui.colors {
		fmt.Printf("\033[1;36m⏳ %s\033[0m", message)
	} else {
		fmt.Printf("⏳ %s", message)
	}
}

func (ui *UI) PrintProgressWithTime(message string, estimatedTime time.Duration) {
	if ui.colors {
		fmt.Printf("\033[1;36m⏳ %s\033[0m \033[90m(~%v)\033[0m", message, estimatedTime.Round(time.Second))
	} else {
		fmt.Printf("⏳ %s (~%v)", message, estimatedTime.Round(time.Second))
	}
}

func (ui *UI) CompleteProgress() {
	if ui.colors {
		fmt.Printf(" \033[1;32m✓\033[0m\n")
	} else {
		fmt.Printf(" ✓\n")
	}
}

func (ui *UI) ShowTimedProgress(message string, duration time.Duration) {
	if !ui.verbose {
		return
	}
	
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	start := time.Now()
	estimatedStr := fmt.Sprintf("(~%v)", duration.Round(time.Second))
	
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	i := 0
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(start)
			if elapsed >= duration {
				fmt.Printf("\r")
				return
			}
			
			remaining := duration - elapsed
			remainingStr := fmt.Sprintf("(~%v remaining)", remaining.Round(time.Second))
			
			if ui.colors {
				fmt.Printf("\r\033[1;36m%s %s\033[0m \033[90m%s\033[0m", 
					spinner[i%len(spinner)], message, remainingStr)
			} else {
				fmt.Printf("\r%s %s %s", spinner[i%len(spinner)], message, remainingStr)
			}
			i++
		}
	}
}

func (ui *UI) ShowProgressBar(current, total int, message string) {
	percentage := float64(current) / float64(total)
	barWidth := 30
	filled := int(percentage * float64(barWidth))
	
	bar := ""
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "█"
		} else if i == filled {
			bar += "▌"
		} else {
			bar += "░"
		}
	}
	
	if ui.colors {
		fmt.Printf("\r\033[1;36m⏳ %s\033[0m \033[1;32m[%s]\033[0m \033[90m%d%%\033[0m", 
			message, bar, int(percentage*100))
	} else {
		fmt.Printf("\r⏳ %s [%s] %d%%", message, bar, int(percentage*100))
	}
	
	if current == total {
		fmt.Printf(" \033[1;32m✓\033[0m\n")
	} else {
		fmt.Printf("\n")
	}
}

func (ui *UI) PrintStepWithTime(current, total int, description string, estimatedTime time.Duration) {
	step := fmt.Sprintf("Step %d/%d", current, total)
	timeStr := fmt.Sprintf("~%v", estimatedTime.Round(time.Second))
	if ui.colors {
		fmt.Printf("\033[1;33m🔧 %s\033[0m \033[1m%s\033[0m \033[90m(%s)\033[0m\n", step, description, timeStr)
	} else {
		fmt.Printf("🔧 %s %s (%s)\n", step, description, timeStr)
	}
}

func (ui *UI) AskYesNo(question string) bool {
	for {
		if ui.colors {
			fmt.Printf("\033[1;35m🤔 %s\033[0m \033[1m(y/n):\033[0m ", question)
		} else {
			fmt.Printf("🤔 %s (y/n): ", question)
		}
		
		var response string
		fmt.Scanln(&response)
		
		response = strings.ToLower(strings.TrimSpace(response))
		switch response {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			ui.PrintWarning("Please enter 'y' or 'n'")
		}
	}
}

func (ui *UI) AskChoice(question string, options []string) int {
	for {
		if ui.colors {
			fmt.Printf("\033[1;35m🎯 %s\033[0m\n", question)
		} else {
			fmt.Printf("🎯 %s\n", question)
		}
		
		for i, option := range options {
			fmt.Printf("  %d) %s\n", i+1, option)
		}
		
		if ui.colors {
			fmt.Printf("\033[1mChoice (1-%d):\033[0m ", len(options))
		} else {
			fmt.Printf("Choice (1-%d): ", len(options))
		}
		
		var choice int
		fmt.Scanln(&choice)
		
		if choice >= 1 && choice <= len(options) {
			return choice - 1
		}
		
		ui.PrintWarning(fmt.Sprintf("Please enter a number between 1 and %d", len(options)))
	}
}

func (ui *UI) ShowSpinner(duration time.Duration, message string) {
	if !ui.verbose {
		return
	}
	
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	start := time.Now()
	
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	i := 0
	for {
		select {
		case <-ticker.C:
			if time.Since(start) >= duration {
				fmt.Printf("\r")
				return
			}
			if ui.colors {
				fmt.Printf("\r\033[1;36m%s %s\033[0m", spinner[i%len(spinner)], message)
			} else {
				fmt.Printf("\r%s %s", spinner[i%len(spinner)], message)
			}
			i++
		}
	}
}

func (ui *UI) ShowVhostConfirmation(domain, configPath, serverType string) {
	if ui.colors {
		fmt.Printf("\n\033[1;33m🔍 Virtual Host Detection\033[0m\n")
		fmt.Printf("Domain: \033[1m%s\033[0m\n", domain)
		fmt.Printf("Server Type: \033[1m%s\033[0m\n", serverType)
		if configPath != "" {
			fmt.Printf("Config File: \033[1m%s\033[0m\n", configPath)
		} else {
			fmt.Printf("Config File: \033[33mNo existing vhost found - will create new SSL config\033[0m\n")
		}
	} else {
		fmt.Printf("\n🔍 Virtual Host Detection\n")
		fmt.Printf("Domain: %s\n", domain)
		fmt.Printf("Server Type: %s\n", serverType)
		if configPath != "" {
			fmt.Printf("Config File: %s\n", configPath)
		} else {
			fmt.Printf("Config File: No existing vhost found - will create new SSL config\n")
		}
	}
}

func (ui *UI) ShowSSLStatus(domain string, sslEnabled bool) {
	if ui.colors {
		fmt.Printf("\n\033[1;33m🔒 SSL Status Check\033[0m\n")
		fmt.Printf("Domain: \033[1m%s\033[0m\n", domain)
		if sslEnabled {
			fmt.Printf("Status: \033[1;32m✅ SSL Already Enabled\033[0m\n")
		} else {
			fmt.Printf("Status: \033[1;31m❌ SSL Not Configured\033[0m\n")
		}
	} else {
		fmt.Printf("\n🔒 SSL Status Check\n")
		fmt.Printf("Domain: %s\n", domain)
		if sslEnabled {
			fmt.Printf("Status: ✅ SSL Already Enabled\n")
		} else {
			fmt.Printf("Status: ❌ SSL Not Configured\n")
		}
	}
}

func (ui *UI) ShowProviderInfo(provider string) {
	if ui.colors {
		fmt.Printf("\n\033[1;33m🏢 Certificate Provider\033[0m\n")
		switch provider {
		case "digicert":
			fmt.Printf("Provider: \033[1;35mDigiCert ACME\033[0m (Commercial)\n")
		case "letsencrypt":
			fmt.Printf("Provider: \033[1;32mLet's Encrypt\033[0m (Free)\n")
		default:
			fmt.Printf("Provider: \033[1m%s\033[0m\n", provider)
		}
	} else {
		fmt.Printf("\n🏢 Certificate Provider\n")
		switch provider {
		case "digicert":
			fmt.Printf("Provider: DigiCert ACME (Commercial)\n")
		case "letsencrypt":
			fmt.Printf("Provider: Let's Encrypt (Free)\n")
		default:
			fmt.Printf("Provider: %s\n", provider)
		}
	}
}

func (ui *UI) ShowValidationResults(domain string, passed bool, details string) {
	if ui.colors {
		fmt.Printf("\n\033[1;33m🔍 Domain Validation\033[0m\n")
		fmt.Printf("Domain: \033[1m%s\033[0m\n", domain)
		if passed {
			fmt.Printf("Result: \033[1;32m✅ Validation Successful\033[0m\n")
		} else {
			fmt.Printf("Result: \033[1;31m❌ Validation Failed\033[0m\n")
		}
		if details != "" {
			fmt.Printf("Details: %s\n", details)
		}
	} else {
		fmt.Printf("\n🔍 Domain Validation\n")
		fmt.Printf("Domain: %s\n", domain)
		if passed {
			fmt.Printf("Result: ✅ Validation Successful\n")
		} else {
			fmt.Printf("Result: ❌ Validation Failed\n")
		}
		if details != "" {
			fmt.Printf("Details: %s\n", details)
		}
	}
}

func (ui *UI) ShowInstallationSummary(domain, provider, serverType string, certPath string) {
	if ui.colors {
		fmt.Printf("\n\033[1;32m🎉 Installation Complete!\033[0m\n")
		fmt.Printf("Domain: \033[1m%s\033[0m\n", domain)
		fmt.Printf("Provider: \033[1m%s\033[0m\n", provider)
		fmt.Printf("Server: \033[1m%s\033[0m\n", serverType)
		fmt.Printf("Certificate: \033[1m%s\033[0m\n", certPath)
		fmt.Printf("\n\033[1;33m📋 Next Steps:\033[0m\n")
		fmt.Printf("1. Restart your web server to apply changes\n")
		fmt.Printf("2. Visit https://%s to verify SSL is working\n", domain)
		fmt.Printf("3. Set up automatic renewal: trusttls renew\n")
	} else {
		fmt.Printf("\n🎉 Installation Complete!\n")
		fmt.Printf("Domain: %s\n", domain)
		fmt.Printf("Provider: %s\n", provider)
		fmt.Printf("Server: %s\n", serverType)
		fmt.Printf("Certificate: %s\n", certPath)
		fmt.Printf("\n📋 Next Steps:\n")
		fmt.Printf("1. Restart your web server to apply changes\n")
		fmt.Printf("2. Visit https://%s to verify SSL is working\n", domain)
		fmt.Printf("3. Set up automatic renewal: trusttls renew\n")
	}
}

func (ui *UI) ShowErrorWithHelp(err error, helpText string) {
	if ui.colors {
		fmt.Printf("\n\033[1;31m💥 Something went wrong!\033[0m\n")
		fmt.Printf("\033[1;31mError:\033[0m %s\n", err.Error())
		if helpText != "" {
			fmt.Printf("\n\033[1;33m💡 How to fix this:\033[0m\n")
			fmt.Printf("%s\n", helpText)
		}
		fmt.Printf("\n\033[1;36m🆘 Need help?\033[0m Visit: https://github.com/trustctl/trusttls/issues\n")
	} else {
		fmt.Printf("\n💥 Something went wrong!\n")
		fmt.Printf("Error: %s\n", err.Error())
		if helpText != "" {
			fmt.Printf("\n💡 How to fix this:\n")
			fmt.Printf("%s\n", helpText)
		}
		fmt.Printf("\n🆘 Need help? Visit: https://github.com/trustctl/trusttls/issues\n")
	}
}

func isTerminal() bool {
	stat, _ := os.Stdout.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}
