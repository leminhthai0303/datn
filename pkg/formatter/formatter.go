package formatter

import (
	"fmt"
	"strings"

	"lemita/datn/pkg/eventlog"
)

// FormatLogEntry creates a human-readable string representation of an event log entry
func FormatLogEntry(log eventlog.EventLogData, index int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nLog #%d:\n", index+1))
	sb.WriteString(fmt.Sprintf("  Source: %s\n", log.SourceName))
	sb.WriteString(fmt.Sprintf("  Computer: %s\n", log.ComputerName))
	sb.WriteString(fmt.Sprintf("  EventID: %d\n", log.EventID))
	sb.WriteString(fmt.Sprintf("  Type: %s\n", eventlog.GetEventTypeName(log.EventType)))
	sb.WriteString(fmt.Sprintf("  Category: %d\n", log.EventCategory))
	sb.WriteString(fmt.Sprintf("  Time: %s\n", eventlog.WindowsTimeToTime(log.TimeGenerated)))

	if len(log.Strings) > 0 {
		sb.WriteString("  Messages:\n")
		for j, msg := range log.Strings {
			sb.WriteString(fmt.Sprintf("    %d: %s\n", j+1, msg))
		}
	}

	return sb.String()
}

// FormatLogChannel formats all logs from a particular channel
func FormatLogChannel(channel string, logs []eventlog.EventLogData) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Found %d logs in %s channel\n", len(logs), channel))

	if len(logs) == 0 {
		sb.WriteString("No matching events found with the specified Event IDs in this channel.\n")
	} else {
		for i, log := range logs {
			sb.WriteString(FormatLogEntry(log, i))
		}
	}

	sb.WriteString(strings.Repeat("-", 50) + "\n")

	return sb.String()
}
