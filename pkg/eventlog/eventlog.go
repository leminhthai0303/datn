package eventlog

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API constants
const (
	ERROR_SUCCESS       = 0
	ERROR_NO_MORE_ITEMS = 259

	EVENTLOG_SEQUENTIAL_READ = 0x0001
	EVENTLOG_BACKWARDS_READ  = 0x0008
	EVENTLOG_SEEK_READ       = 0x0002
	EVENTLOG_FORWARDS_READ   = 0x0004

	EVENTLOG_SUCCESS          = 0x0000
	EVENTLOG_ERROR_TYPE       = 0x0001
	EVENTLOG_WARNING_TYPE     = 0x0002
	EVENTLOG_INFORMATION_TYPE = 0x0004
	EVENTLOG_AUDIT_SUCCESS    = 0x0008
	EVENTLOG_AUDIT_FAILURE    = 0x0010
)

// EVENTLOGRECORD structure
type EVENTLOGRECORD struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

// Size of the EVENTLOGRECORD structure - used for buffer management
const sizeof_EVENTLOGRECORD = 56 // Sum of all fields sizes

// EventLogData represents a processed event log entry
type EventLogData struct {
	RecordNumber  uint32
	TimeGenerated uint32
	TimeWritten   uint32
	EventID       uint32
	EventType     uint16
	EventCategory uint16
	SourceName    string
	ComputerName  string
	Strings       []string
	Data          []byte
}

// GetLocalComputerName retrieves the name of the local computer
func GetLocalComputerName() string {
	var size uint32 = 64
	buffer := make([]uint16, size)

	// Use the Windows GetComputerNameW API
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getComputerName := kernel32.NewProc("GetComputerNameW")

	ret, _, _ := getComputerName.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret != 0 {
		return syscall.UTF16ToString(buffer[:size])
	}

	return "Unknown"
}

// GetSourceFromEvent extracts the source name from an event log record
func GetSourceFromEvent(logName string, record *EVENTLOGRECORD, buffer []byte, offset uint32) string {
	// First, try to extract from the buffer
	sourceStart := offset + 8*4 // Start of strings after the record header
	sourceEnd := sourceStart

	// Make sure we don't go out of bounds
	for sourceEnd+1 < uint32(len(buffer)) && (buffer[sourceEnd] != 0 || buffer[sourceEnd+1] != 0) {
		sourceEnd += 2
		// Safety check to prevent infinite loops
		if sourceEnd-sourceStart > 1024 {
			break
		}
	}

	// Safe string conversion with length check
	strLen := (sourceEnd - sourceStart) / 2
	if strLen > 0 && strLen < 1024 {
		sourceName := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(&buffer[sourceStart]))[:strLen])
		if sourceName != "" {
			return sourceName
		}
	}

	// Fallback options if direct extraction failed

	// For well-known logs, use the channel name
	if logName == "System" || logName == "Application" || logName == "Security" {
		return logName
	}

	// Try to extract from the log name for Microsoft-Windows-* channels
	if strings.HasPrefix(logName, "Microsoft-Windows-") {
		parts := strings.Split(logName, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Last resort fallback
	return "EventLog"
}

// WindowsTimeToTime converts a Windows timestamp to human-readable format
func WindowsTimeToTime(windowsTime uint32) string {
	// Windows time is number of seconds since 1970-01-01 UTC
	unixTime := int64(windowsTime)
	t := syscall.NsecToTimeval(unixTime * 1e9)

	// Format: YYYY-MM-DD HH:MM:SS
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		1970+t.Sec/31536000,
		(t.Sec%31536000)/2592000+1,
		((t.Sec%31536000)%2592000)/86400+1,
		((t.Sec%31536000)%2592000)%86400/3600,
		(((t.Sec%31536000)%2592000)%86400)%3600/60,
		(((t.Sec%31536000)%2592000)%86400)%3600%60,
	)
}

// GetEventTypeName returns a human-readable name for an event type
func GetEventTypeName(eventType uint16) string {
	switch eventType {
	case EVENTLOG_SUCCESS:
		return "Success"
	case EVENTLOG_ERROR_TYPE:
		return "Error"
	case EVENTLOG_WARNING_TYPE:
		return "Warning"
	case EVENTLOG_INFORMATION_TYPE:
		return "Information"
	case EVENTLOG_AUDIT_SUCCESS:
		return "Audit Success"
	case EVENTLOG_AUDIT_FAILURE:
		return "Audit Failure"
	default:
		return fmt.Sprintf("Unknown (%d)", eventType)
	}
}

// CollectWindowsEventLogs retrieves events from the specified Windows Event Log channel
func CollectWindowsEventLogs(logName string, maxEvents int, specificEventIDs []uint32) ([]EventLogData, error) {
	// Get local computer name for fallback
	localComputerName := GetLocalComputerName()

	// Load the required DLLs
	advapi32 := syscall.NewLazyDLL("advapi32.dll")

	// Get the required procedures
	openEventLog := advapi32.NewProc("OpenEventLogW")
	closeEventLog := advapi32.NewProc("CloseEventLog")
	readEventLog := advapi32.NewProc("ReadEventLogW")
	getNumberOfEventLogRecords := advapi32.NewProc("GetNumberOfEventLogRecords")

	// Convert logName to UTF16
	logNameUTF16, err := syscall.UTF16PtrFromString(logName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert log name to UTF16: %v", err)
	}

	// Try to open the event log
	var handle uintptr
	serverNameUTF16, _ := syscall.UTF16PtrFromString("")
	ret, _, err := openEventLog.Call(
		uintptr(unsafe.Pointer(serverNameUTF16)),
		uintptr(unsafe.Pointer(logNameUTF16)),
	)

	if ret == 0 {
		// Special handling for common case where log doesn't exist
		// This handles non-default channels like Sysmon that might not be installed
		if err.(syscall.Errno) == syscall.ERROR_FILE_NOT_FOUND {
			return nil, fmt.Errorf("event log '%s' not found - this channel may not be available on this system", logName)
		}
		return nil, fmt.Errorf("failed to open event log: %v", err)
	}
	handle = ret
	defer closeEventLog.Call(handle)

	// Get total number of records
	var totalRecords uint32
	ret, _, _ = getNumberOfEventLogRecords.Call(
		handle,
		uintptr(unsafe.Pointer(&totalRecords)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("failed to get number of event log records")
	}

	// Limit the number of events to read
	if maxEvents > 0 && int(totalRecords) > maxEvents {
		totalRecords = uint32(maxEvents)
	}

	logs := make([]EventLogData, 0, totalRecords)

	// Read the events
	bufferSize := uint32(4096) // Initial buffer size
	buffer := make([]byte, bufferSize)
	var bytesRead uint32
	var bytesNeeded uint32

	flags := uint32(EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ)

	for len(logs) < int(totalRecords) {
		ret, _, err = readEventLog.Call(
			handle,
			uintptr(flags),
			0,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(unsafe.Pointer(&bytesNeeded)),
		)

		if ret == 0 {
			errno := err.(syscall.Errno)
			if errno == ERROR_NO_MORE_ITEMS {
				// Reached end of log - this is normal, not an error
				break
			} else if errno == syscall.ERROR_INSUFFICIENT_BUFFER {
				// Resize buffer and try again
				bufferSize = bytesNeeded
				buffer = make([]byte, bufferSize)
				continue
			}
			return logs, fmt.Errorf("error reading event log: %v", err)
		}

		// Process the buffer which may contain multiple event records
		offset := uint32(0)
		for offset < bytesRead {
			// Safety check - make sure we have at least enough space for the record header
			if offset+sizeof_EVENTLOGRECORD > bytesRead {
				break
			}

			record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))

			// Basic validation - check if record length is reasonable
			if record.Length < sizeof_EVENTLOGRECORD || record.Length > bytesRead-offset {
				// Invalid record length, skip to next aligned position or end
				offset += 8 // Try to realign on 8-byte boundary
				if offset >= bytesRead {
					break
				}
				continue
			}

			// Extract event data
			event := EventLogData{
				RecordNumber:  record.RecordNumber,
				TimeGenerated: record.TimeGenerated,
				TimeWritten:   record.TimeWritten,
				EventID:       record.EventID & 0xFFFF, // Low 16 bits
				EventType:     record.EventType,
				EventCategory: record.EventCategory,
				SourceName:    GetSourceFromEvent(logName, record, buffer, offset),
				ComputerName:  localComputerName, // Use the local computer name
			}

			// Get strings - with bounds checking
			event.Strings = make([]string, 0, record.NumStrings)
			if record.NumStrings > 0 && record.StringOffset > 0 {
				stringsPtr := offset + record.StringOffset

				// Safety check - make sure StringOffset is within buffer bounds
				if stringsPtr < uint32(len(buffer)) {
					for i := uint16(0); i < record.NumStrings; i++ {
						// Check if we're still within buffer
						if stringsPtr >= uint32(len(buffer)) {
							break
						}

						strStart := stringsPtr
						strEnd := strStart

						// Find null terminator with bounds checking
						for strEnd+1 < uint32(len(buffer)) && (buffer[strEnd] != 0 || buffer[strEnd+1] != 0) {
							strEnd += 2
							// Safety check for overly long strings
							if strEnd-strStart > 32768 { // Max reasonable string length
								break
							}
						}

						// Safe string conversion
						strLen := (strEnd - strStart) / 2
						if strLen > 0 && strLen < 16384 {
							str := syscall.UTF16ToString((*[16384]uint16)(unsafe.Pointer(&buffer[strStart]))[:strLen])
							event.Strings = append(event.Strings, str)
						}

						// Move to next string (if any)
						if strEnd+2 >= uint32(len(buffer)) {
							break // End of buffer
						}
						stringsPtr = strEnd + 2
					}
				}
			}

			// Get binary data if present - with bounds checking
			if record.DataLength > 0 && record.DataOffset > 0 {
				dataStart := offset + record.DataOffset

				// Make sure offsets are within buffer bounds
				if dataStart < uint32(len(buffer)) {
					dataEnd := dataStart + record.DataLength

					// Ensure we don't go beyond buffer
					if dataEnd > uint32(len(buffer)) {
						dataEnd = uint32(len(buffer))
					}

					if dataEnd > dataStart {
						event.Data = make([]byte, dataEnd-dataStart)
						copy(event.Data, buffer[dataStart:dataEnd])
					}
				}
			}

			// Filter by specific event IDs if provided
			if specificEventIDs != nil && len(specificEventIDs) > 0 {
				eventIDMatches := false
				for _, id := range specificEventIDs {
					if event.EventID == id {
						eventIDMatches = true
						break
					}
				}
				if eventIDMatches {
					logs = append(logs, event)
				}
			} else {
				// No filtering, add all events
				logs = append(logs, event)
			}

			offset += record.Length

			if len(logs) >= int(totalRecords) {
				break
			}
		}
	}

	return logs, nil
}
