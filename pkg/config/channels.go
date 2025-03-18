package config

// ChannelConfig defines the configuration for an event log channel
type ChannelConfig struct {
	Name      string
	Purpose   string
	EventIDs  []uint32
	Available bool // Whether this channel is expected to be available on most systems
}

// GetChannelConfigs returns configuration for all monitored event log channels
func GetChannelConfigs() []ChannelConfig {
	return []ChannelConfig{
		{
			Name:      "Security",
			Purpose:   "User logins, privilege escalation",
			EventIDs:  []uint32{4624, 4625, 4672, 4688, 4720, 4768},
			Available: true,
		},
		{
			Name:    "System",
			Purpose: "System changes, service failures",
			EventIDs: []uint32{6005, 6006, 7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
				7011, 7012, 7013, 7014, 7015, 7016, 7017, 7018, 7019, 7020, 7021, 7022, 7023,
				7045, 1102},
			Available: true,
		},
		{
			Name:      "Application",
			Purpose:   "App crashes, service failures",
			EventIDs:  []uint32{1000, 7034, 5000},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-PowerShell/Operational",
			Purpose:   "PowerShell execution tracking",
			EventIDs:  []uint32{4103, 4104, 4105, 4106},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-Windows Defender/Operational",
			Purpose:   "Malware detection",
			EventIDs:  []uint32{1006, 1116, 5007},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-Sysmon/Operational",
			Purpose:   "Process and network monitoring",
			EventIDs:  []uint32{1, 3, 7, 11, 13},
			Available: false, // Sysmon is not installed by default
		},
		{
			Name:      "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			Purpose:   "RDP connections",
			EventIDs:  []uint32{21, 24, 25},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-TaskScheduler/Operational",
			Purpose:   "Scheduled task creation",
			EventIDs:  []uint32{106, 140, 141},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-GroupPolicy/Operational",
			Purpose:   "GPO changes",
			EventIDs:  []uint32{1502, 1503},
			Available: true,
		},
		{
			Name:      "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
			Purpose:   "Network connections, rule changes",
			EventIDs:  []uint32{2004, 2006, 5156, 5152},
			Available: true,
		},
	}
}
