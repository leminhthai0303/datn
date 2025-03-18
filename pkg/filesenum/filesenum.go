package filesenum

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	OpenSCManager        = advapi32.NewProc("OpenSCManagerW")
	OpenService          = advapi32.NewProc("OpenServiceW")
	EnumServicesStatusEx = advapi32.NewProc("EnumServicesStatusExW")
	QueryServiceConfig   = advapi32.NewProc("QueryServiceConfigW")
	CloseServiceHandle   = advapi32.NewProc("CloseServiceHandle")
)

const (
	SC_MANAGER_ALL_ACCESS        = 0xF003F
	SC_MANAGER_ENUMERATE_SERVICE = 0x0004
	SERVICE_QUERY_CONFIG         = 0x0001
)

type PEInfo struct {
	FilePath string
	Hash     string
	Name     string
}

type ENUM_SERVICE_STATUS_PROCESS struct {
	ServiceName   *uint16
	DisplayName   *uint16
	StatusProcess SERVICE_STATUS_PROCESS
}

type QUERY_SERVICE_CONFIG struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagId            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

type SERVICE_STATUS_PROCESS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

func extractExecutablePath(binaryPath string) string {
	// Remove surrounding quotes if present
	path := binaryPath
	if len(path) > 0 && (path[0] == '"' || path[0] == '\'') {
		// Find the matching closing quote
		for i := 1; i < len(path); i++ {
			if path[i] == path[0] {
				path = path[1:i]
				break
			}
		}
	} else {
		// No quotes, so the executable path ends at the first space (arguments follow)
		spaceIndex := strings.Index(path, " ")
		if spaceIndex > 0 {
			path = path[:spaceIndex]
		}
	}

	// Expand environment variables like %SystemRoot%
	if strings.Contains(path, "%") {
		// Extract environment variable name
		for {
			startIdx := strings.Index(path, "%")
			if startIdx == -1 {
				break
			}
			endIdx := strings.Index(path[startIdx+1:], "%")
			if endIdx == -1 {
				break
			}
			endIdx += startIdx + 1

			envVar := path[startIdx+1 : endIdx]
			envValue := os.Getenv(envVar)

			// Replace the environment variable with its value
			path = path[:startIdx] + envValue + path[endIdx+1:]
		}
	}

	return path
}

func getSHA256Hash(binaryPath string) (string, error) {
	// Extract the actual executable path from the service binary path
	executablePath := extractExecutablePath(binaryPath)

	// Try to open the file
	file, err := os.Open(executablePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %v", executablePath, err)
	}
	defer file.Close()

	// Calculate hash
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to read file %s: %v", executablePath, err)
	}

	sum := hash.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}

func GetServiceBinaryPath(scManager uintptr, serviceName *uint16) (string, error) {
	serviceHandle, _, err := OpenService.Call(
		scManager,
		uintptr(unsafe.Pointer(serviceName)),
		SERVICE_QUERY_CONFIG,
	)

	if serviceHandle == 0 {
		return "", fmt.Errorf("OpenService failed: %v", err)
	}
	defer CloseServiceHandle.Call(serviceHandle)

	var bytesNeeded uint32
	QueryServiceConfig.Call(
		serviceHandle,
		0,
		0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if bytesNeeded == 0 {
		return "", fmt.Errorf("QueryServiceConfig failed to return buffer size")
	}

	buffer := make([]byte, bytesNeeded)
	ret, _, err := QueryServiceConfig.Call(
		serviceHandle,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if ret == 0 {
		return "", fmt.Errorf("QueryServiceConfig failed: %v", err)
	}

	config := (*QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	binaryPath := windows.UTF16PtrToString(config.BinaryPathName)

	return binaryPath, nil
}

func ListServices() ([]PEInfo, error) {
	var peList []PEInfo

	// Open the service control manager
	scManager, _, err0 := OpenSCManager.Call(0, 0, SC_MANAGER_ENUMERATE_SERVICE)
	if scManager == 0 {
		return nil, fmt.Errorf("OpenSCManager failed: %v", err0)
	}
	defer CloseServiceHandle.Call(scManager)

	var bufSize uint32
	var bytesNeeded uint32
	var servicesReturned uint32
	var resumeHandle uint32

	// First call to get required buffer size
	EnumServicesStatusEx.Call(
		uintptr(scManager),
		0,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		0,
		0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	// Allocate buffer and call again to get actual data
	bufSize = bytesNeeded
	buf := make([]byte, bufSize)
	ret, _, err2 := EnumServicesStatusEx.Call(
		uintptr(scManager),
		0,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx failed: %v", err2)
	}

	// Process each service
	for i := uint32(0); i < servicesReturned; i++ {
		// Calculate offset for the current service
		offset := unsafe.Sizeof(ENUM_SERVICE_STATUS_PROCESS{})
		servicePtr := uintptr(unsafe.Pointer(&buf[0])) + uintptr(i)*offset

		// Get a pointer to the current service
		service := (*ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(servicePtr))

		serviceName := windows.UTF16PtrToString(service.ServiceName)
		displayName := windows.UTF16PtrToString(service.DisplayName)

		// Get the binary path
		binaryPath, err := GetServiceBinaryPath(scManager, service.ServiceName)
		if err != nil {
			fmt.Printf("Warning: Could not get binary path for service %s: %v\n", serviceName, err)
			continue
		}

		// Calculate hash for the binary
		hash, err := getSHA256Hash(binaryPath)
		if err != nil {
			fmt.Printf("Warning: Could not calculate hash for %s: %v\n", binaryPath, err)
			hash = "hash-unavailable"
		}

		// Add to our list
		info := PEInfo{
			FilePath: binaryPath,
			Hash:     hash,
			Name:     displayName,
		}
		peList = append(peList, info)
	}

	return peList, nil
}
