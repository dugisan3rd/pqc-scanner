package main

import (
	"fmt"
	"io"
	"mini-pqc/cmd/commands/linux"
	"mini-pqc/pkg/config"
	"mini-pqc/scan"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Version is set during build via -ldflags
// This version follows semantic versioning with patch increments on source changes
var Version = "0.1.0"

// Global variables
var availableCommands = []string{
	"help",
	"exit",
	"version",   // Show version information
	"tls",       //20
	"lib",       //14
	"env",       //1
	"firmware",  //2
	"nginx",     //5
	"apache",    //15
	"wireguard", //16
	"openssh",   //8
	"openvpn",   //7
	"ipsec",     //4
	"ca",        //11
	"runtime",   //10
	"postfix",   //13
	"parsecrt",  //12
	"pgp",       //9
	"kernel",    //3
	"tcpdump",   //17
	"all",
}

// Global recommendation manager
var recManager *scan.RecommendationManager
var cliMode bool // Flag to indicate if running in CLI mode (without UI)

// Global UI components
var notesPanel *tview.TextView
var scrollBar *tview.TextView
var totalLines int
var visibleLines int
var currentScrollPos int

// Command descriptor struct
type Cmd struct {
	NeedsConfig bool // skip validation for help/exit etc.
	Handler     func(args []string) []scan.Recommendation
	Desc        string
}

// Command registration map
var commands map[string]Cmd

// Initialize commands map
func initCommands() {
	commands = map[string]Cmd{
		"help": {
			Handler: func(_ []string) []scan.Recommendation {
				printHelp()
				return nil
			},
			Desc: "Show available commands",
		},
		"exit": {
			Handler: func(_ []string) []scan.Recommendation {
				fmt.Println("Exiting application.")
				os.Exit(0)
				return nil
			},
			Desc: "Exit the application",
		},
		"version": {
			Handler: func(_ []string) []scan.Recommendation {
				fmt.Printf("PQC Scanner version: %s (built with Go)\n", Version)
				return nil
			},
			Desc: "Show version information",
		},
		"tls": {
			NeedsConfig: true,
			Handler: func(args []string) []scan.Recommendation {
				domain := firstOr(args, "example.com")
				scanner := scan.NewTLSScanner()
				return linux.TestTLD(scanner, domain)
			},
			Desc: "Test TLS configuration for a domain",
		},
		"lib":       simpleJSON(linux.TestLib, "Test cryptographic libraries"),
		"env":       simpleJSON(linux.Env, "Check environment security"),
		"firmware":  simpleJSON(linux.Firmware, "Check firmware security"),
		"nginx":     simpleJSON(linux.TestNginx, "Check Nginx configuration"),
		"apache":    simpleJSON(linux.TestApache, "Check Apache configuration"),
		"wireguard": simpleJSON(linux.TestWireguard, "Check WireGuard configuration"),
		"openssh":   simpleJSON(linux.TestOpenSSH, "Check OpenSSH configuration"),
		"openvpn":   simpleJSON(linux.TestOpenVPN, "Check OpenVPN configuration"),
		"ipsec":     simpleJSON(linux.TestIPsec, "Check IPsec configuration"),
		"ca":        simpleJSON(linux.TestCA, "Check Certificate Authority configuration"),
		"apps":      simpleJSON(linux.Apps, "Check installed applications"),
		"runtime":   simpleJSON(linux.TestRuntime, "Check runtime environment for PQC readiness"),
		"postfix":   simpleJSON(linux.TestPostfix, "Check Postfix configuration for PQC readiness"),
		"pgp":       simpleJSON(linux.TestPGP, "Check PGP configuration for PQC readiness"),
		"kernel":    simpleJSON(linux.TestKernel, "Check kernel configuration for PQC readiness"),

		"testtcpdump": {
			NeedsConfig: true,
			Handler: func(args []string) []scan.Recommendation {
				// Check for -dump parameter anywhere in args
				for _, arg := range args {
					if arg == "-dump" {
						// Just run the command without displaying recommendations
						linux.TestTcpdump(args...)
						return nil
					}
				}
				if len(args) > 0 {
					return linux.TestTcpdump(args...)
				}
				return linux.TestTcpdump()
			},
			Desc: "Test network traffic capture with tcpdump",
		},
		"tcpdump": {
			NeedsConfig: true,
			Handler: func(args []string) []scan.Recommendation {
				// Check for -list parameter
				if len(args) > 0 && args[0] == "-list" {
					linux.TestTcpdump(args...)
					return nil
				}
				// Check for -dump parameter anywhere in args
				for _, arg := range args {
					if arg == "-dump" {
						linux.TestTcpdump(args...)
						return nil
					}
				}
				if len(args) > 0 {
					return linux.TestTcpdump(args...)
				}
				return linux.TestTcpdump()
			},
			Desc: "Test network traffic capture with tcpdump",
		},
		"parsecrt": {
			NeedsConfig: true,
			Handler: func(args []string) []scan.Recommendation {
				verbose := false
				jsonOutput := false
				for _, arg := range args {
					if arg == "-verbose" {
						verbose = true
					}
					if arg == "-json" {
						jsonOutput = true
					}
				}
				return linux.ParseCrt(verbose, jsonOutput)
			},
			Desc: "Parse and analyze certificates",
		},
		"all": {
			NeedsConfig: true,
			Handler: func(args []string) []scan.Recommendation {
				jsonOutput := false
				if len(args) > 0 && args[0] == "-json" {
					jsonOutput = true
				}
				if !jsonOutput {
					fmt.Println("Running comprehensive scan with all modules...")
				}
				recs := linux.RunAllCommands(jsonOutput)
				if jsonOutput {
					// Return nil to prevent displayRecommendations from being called
					return nil
				}
				return recs
			},
			Desc: "Run all scan commands",
		},
	}
}

// Helper function for simple JSON flag commands
func simpleJSON(
	fn func(json bool) []scan.Recommendation,
	desc string,
) Cmd {
	return Cmd{
		NeedsConfig: true,
		Handler: func(args []string) []scan.Recommendation {
			return fn(len(args) > 0 && args[0] == "-json")
		},
		Desc: desc,
	}
}

// Helper function to get first argument or default
func firstOr(args []string, def string) string {
	if len(args) > 0 {
		return args[0]
	}
	return def
}

// Helper function to validate configuration
func validateConfig() bool {
	if !config.ConfigFileExists() {
		fmt.Println("Error: Configuration file not found.")
		fmt.Println("Please run 'pqc config' to set up your configuration.")
		return false
	}
	if !config.IsConfigValid() {
		fmt.Println("Error: Configuration is incomplete.")
		fmt.Println("Please run 'pqc config' to set organization name and license key.")
		return false
	}
	return true
}

// Command executor function
func executor(in string) {
	parts := strings.Fields(strings.TrimSpace(in))
	if len(parts) == 0 {
		return
	}
	name, args := parts[0], parts[1:]

	cmd, ok := commands[name]
	if !ok {
		fmt.Println("Unknown command. Type 'help' for available commands.")
		return
	}

	if cmd.NeedsConfig && !validateConfig() {
		return
	}

	recs := cmd.Handler(args)
	if recs == nil { // e.g. help/exit did their own printing
		return
	}
	recManager.AppendRecommendations(recs)
	displayRecommendations(recManager.FormatRecommendations())
}

// Completer function for tab completion
func completer(d prompt.Document) []prompt.Suggest {
	word := d.GetWordBeforeCursor()
	var sugg []prompt.Suggest
	for name, c := range commands {
		sugg = append(sugg, prompt.Suggest{Text: name, Description: c.Desc})
	}
	return prompt.FilterHasPrefix(sugg, word, true)
}

// Print help information
func printHelp() {
	fmt.Println("Available commands:")
	for name, c := range commands {
		if c.Desc != "" {
			fmt.Printf("  %-12s - %s\n", name, c.Desc)
		}
	}
	fmt.Println("\nFeatures:")
	fmt.Println("  - Type commands and press Enter to execute")
	fmt.Println("  - Use 'exit' to quit the application")
}

func main() {
	// Initialize commands map
	initCommands()

	// Share version with linux package
	linux.Version = Version

	// Initialize recommendation manager
	recManager = scan.NewRecommendationManager()

	// Check if command-line arguments are provided
	args := os.Args
	if len(args) > 1 {
		// Set CLI mode flag
		cliMode = true
		// Command provided as CLI argument
		executor(strings.Join(args[1:], " "))
		return
	}

	// Create tview application
	app := tview.NewApplication()

	// Create CLI panel (left side) - combines input and output
	cliPanel := tview.NewTextView()
	cliPanel.SetDynamicColors(true)
	cliPanel.SetScrollable(true)
	cliPanel.SetTitle("PQC Scanner CLI")
	cliPanel.SetBorder(true)
	cliPanel.SetText("[green]PQC Scanner - Post-Quantum Cryptography Scanning Tool[white]\n" +
		"Type commands below. Type 'help' to see available commands.\n")

	// Create command input
	commandPanel := tview.NewInputField()
	commandPanel.SetLabel("[green]>>> [white]")
	commandPanel.SetFieldWidth(0)
	commandPanel.SetFieldBackgroundColor(tcell.ColorBlack)
	commandPanel.SetFieldTextColor(tcell.ColorGreen)

	// Initialize global notes panel (right side)
	notesPanel = tview.NewTextView()
	notesPanel.SetDynamicColors(true)
	notesPanel.SetScrollable(true)
	notesPanel.SetTitle("PQC Scanner Notes")
	notesPanel.SetBorder(true)
	notesPanel.SetText("Welcome to PQC Scanner\n\nRun commands in the CLI panel to generate recommendations.")

	// Run env command by default to populate the notes panel
	envOutput := captureOutput(func() {
		executor("env")
	})

	// Update CLI panel with the actual env command output
	currentText := cliPanel.GetText(false)
	cliPanel.SetText(fmt.Sprintf("%s\n[green]>>> env[white]\n%s", currentText, envOutput))

	// Create CLI layout (input at bottom of CLI panel)
	cliLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cliPanel, 0, 1, false).
		AddItem(commandPanel, 1, 0, true)

	// Create scrollbar for notes panel
	scrollBar = tview.NewTextView()
	scrollBar.SetDynamicColors(true)
	scrollBar.SetScrollable(false)
	scrollBar.SetBorder(false)
	scrollBar.SetBackgroundColor(tcell.ColorDarkGray)
	scrollBar.SetTextColor(tcell.ColorWhite)
	
	// Initialize scrollbar with initial content
	updateScrollBar()

	// Update scrollbar on notes panel scroll
	notesPanel.SetChangedFunc(func() {
		updateScrollBar()
	})
	
	// Create notes panel with scrollbar (notes panel + thin scrollbar)
	notesLayout := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(notesPanel, 0, 1, false).
		AddItem(scrollBar, 1, 0, false)

	// Create main layout - CLI on left, notes on right
	mainLayout := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(cliLayout, 0, 3, true).
		AddItem(notesLayout, 0, 2, false)

	// Execute command when Enter is pressed
	commandPanel.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			cmd := commandPanel.GetText()
			if cmd == "" {
				return
			}

			// Handle exit command
			if cmd == "exit" {
				app.Stop()
				return
			}

			// Redirect stdout to capture command output
			output := captureOutput(func() {
				executor(cmd)
			})

			// Update CLI panel with command output
			currentText := cliPanel.GetText(false)
			newText := fmt.Sprintf("%s\n[green]>>> %s[white]\n%s", currentText, cmd, output)
			cliPanel.SetText(newText)
			cliPanel.ScrollToEnd()

			// Clear command panel
			commandPanel.SetText("")
		}
	})

	// Set up keyboard shortcuts
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab {
			// Toggle focus between panels
			if commandPanel.HasFocus() {
				app.SetFocus(notesPanel)
			} else if notesPanel.HasFocus() {
				app.SetFocus(commandPanel)
			} else { // CLI panel has focus
				app.SetFocus(commandPanel)
			}
			return nil
		}
		
		// Handle scroll events when notes panel has focus
		if notesPanel.HasFocus() {
			switch event.Key() {
			case tcell.KeyUp, tcell.KeyPgUp:
				// Scroll up
				if currentScrollPos > 0 {
					currentScrollPos--
				}
				updateScrollBar()
				return event
			case tcell.KeyDown, tcell.KeyPgDn:
				// Scroll down
				maxScroll := max(0, totalLines-visibleLines)
				if currentScrollPos < maxScroll {
					currentScrollPos++
				}
				updateScrollBar()
				return event
			case tcell.KeyHome:
				// Go to top
				currentScrollPos = 0
				updateScrollBar()
				return event
			case tcell.KeyEnd:
				// Go to bottom
				currentScrollPos = max(0, totalLines-visibleLines)
				updateScrollBar()
				return event
			}
		}
		
		return event
	})

	// Start the application
	if err := app.SetRoot(mainLayout, true).EnableMouse(true).Run(); err != nil {
		fmt.Printf("Error running application: %v\n", err)
	}
}

// displayRecommendations displays recommendations based on mode
func displayRecommendations(content string) {
	if cliMode {
		// Print recommendations to console when in CLI mode
		// Note: The content already includes a "Recommendations" header from FormatRecommendations
		fmt.Println(content)
	} else {
		// Update UI when in interactive mode
		notesPanel.SetText(content)
	}
}

// captureOutput captures stdout during function execution
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	output, err := io.ReadAll(r)
	if err != nil {
		return fmt.Sprintf("Error capturing output: %v", err)
	}

	return string(output)
}

func updateScrollBar() {
	// Create a visual scrollbar indicator
	// Calculate approximate scroll position based on content length
	content := notesPanel.GetText(false)
	totalLines := len(strings.Split(content, "\n"))
	
	// Estimate visible area (approximate)
	_, _, _, height := notesPanel.GetRect()
	visibleLines := height - 2 // Account for border
	
	if visibleLines <= 0 {
		visibleLines = 10 // Default fallback
	}
	
	// Create scrollbar visual
	scrollBarHeight := 15 // Fixed height for scrollbar
	var scrollBarContent strings.Builder
	
	if totalLines <= visibleLines {
		// Content fits in view, show full scrollbar
		scrollBarContent.WriteString("[darkgray]")
		for i := 0; i < scrollBarHeight; i++ {
			scrollBarContent.WriteString("█\n")
		}
	} else {
		// Content is scrollable, show proportional indicator
		thumbSize := max(1, (visibleLines*scrollBarHeight)/totalLines)
		maxScroll := max(1, totalLines-visibleLines)
		thumbPos := (currentScrollPos * (scrollBarHeight - thumbSize)) / maxScroll
		
		scrollBarContent.WriteString("[darkgray]")
		for i := 0; i < scrollBarHeight; i++ {
			if i >= thumbPos && i < thumbPos+thumbSize {
				scrollBarContent.WriteString("[white]█[darkgray]\n")
			} else {
				scrollBarContent.WriteString("░\n")
			}
		}
	}
	
	scrollBar.SetText(scrollBarContent.String())
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Trivial change to trigger version increment - test update
