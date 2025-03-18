package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lemita/datn/pkg/config"
	"lemita/datn/pkg/eventlog"
	"lemita/datn/pkg/formatter"
)

func main() {
	// Define command line flags
	maxEvents := flag.Int("max", 100, "Maximum number of events to collect per channel")
	outputFile := flag.String("out", "", "Output file path (leave empty for Desktop file, use 'console' for console output)")
	onlyAvailable := flag.Bool("available", true, "Only collect from channels expected to be available")
	specificChannel := flag.String("channel", "", "Collect from a specific channel only (leave empty for all channels)")

	flag.Parse()

	// Get the channel configurations
	channelConfigs := config.GetChannelConfigs()

	// Get desktop path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting user home directory: %v\n", err)
		homeDir = "."
	}
	desktopPath := filepath.Join(homeDir, "Desktop")

	// Prepare output
	var output *os.File
	if *outputFile == "console" {
		// Explicit console output requested
		output = os.Stdout
	} else if *outputFile == "" {
		// Default to a file on the desktop when no output file is specified
		timestamp := time.Now().Format("20060102-150405")
		fileName := filepath.Join(desktopPath, fmt.Sprintf("WindowsEventLogs-%s.log", timestamp))
		output, err = os.Create(fileName)
		if err != nil {
			fmt.Printf("Error creating default output file on desktop: %v\nFalling back to console output.\n", err)
			output = os.Stdout
		} else {
			defer output.Close()
			fmt.Printf("Logging output to: %s\n", fileName)
		}
	} else if !filepath.IsAbs(*outputFile) {
		// If a relative path is provided, put it on the desktop
		timestamp := time.Now().Format("20060102-150405")
		fileName := filepath.Join(desktopPath, fmt.Sprintf("%s-%s.log", strings.TrimSuffix(*outputFile, ".log"), timestamp))
		output, err = os.Create(fileName)
		if err != nil {
			fmt.Printf("Error creating output file on desktop: %v\nFalling back to console output.\n", err)
			output = os.Stdout
		} else {
			defer output.Close()
			fmt.Printf("Logging output to: %s\n", fileName)
		}
	} else {
		// Absolute path was provided
		timestamp := time.Now().Format("20060102-150405")
		fileName := fmt.Sprintf("%s-%s.log", strings.TrimSuffix(*outputFile, ".log"), timestamp)
		output, err = os.Create(fileName)
		if err != nil {
			fmt.Printf("Error creating output file: %v\nFalling back to console output.\n", err)
			output = os.Stdout
		} else {
			defer output.Close()
			fmt.Printf("Logging output to: %s\n", fileName)
		}
	}

	// Print header
	header := fmt.Sprintf("Windows Event Log Collection - %s\n", time.Now().Format(time.RFC1123))
	underline := strings.Repeat("=", len(header)-1) + "\n\n"
	output.WriteString(header + underline)

	totalEventsCollected := 0
	startTime := time.Now()

	// Process channels
	for _, channelConfig := range channelConfigs {
		// Skip if not available and we only want available channels
		if *onlyAvailable && !channelConfig.Available {
			continue
		}

		// Skip if we're looking for a specific channel and this isn't it
		if *specificChannel != "" && !strings.EqualFold(channelConfig.Name, *specificChannel) {
			continue
		}

		collectionMsg := fmt.Sprintf("\nCollecting logs from %s channel (Purpose: %s)...\n",
			channelConfig.Name, channelConfig.Purpose)
		output.WriteString(collectionMsg)

		// Create event ID list string for display
		eventIDStrings := make([]string, len(channelConfig.EventIDs))
		for i, id := range channelConfig.EventIDs {
			eventIDStrings[i] = strconv.FormatUint(uint64(id), 10)
		}
		eventIDsStr := strings.Join(eventIDStrings, ", ")
		output.WriteString(fmt.Sprintf("Looking for Event IDs: %s\n", eventIDsStr))

		// Collect logs
		logs, err := eventlog.CollectWindowsEventLogs(channelConfig.Name, *maxEvents, channelConfig.EventIDs)

		if err != nil {
			errMsg := fmt.Sprintf("Error collecting logs from %s: %v\n", channelConfig.Name, err)
			output.WriteString(errMsg)
			continue
		}

		// Format and write the logs
		formattedLogs := formatter.FormatLogChannel(channelConfig.Name, logs)
		output.WriteString(formattedLogs)

		totalEventsCollected += len(logs)
	}

	// Write summary
	duration := time.Since(startTime)
	summary := fmt.Sprintf("\nSummary\n-------\n")
	summary += fmt.Sprintf("Total events collected: %d\n", totalEventsCollected)
	summary += fmt.Sprintf("Duration: %v\n", duration)
	output.WriteString(summary)

	if *outputFile != "" {
		fmt.Printf("Collection complete. Collected %d events in %v.\n", totalEventsCollected, duration)
	}
}
