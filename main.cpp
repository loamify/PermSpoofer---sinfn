//ImGui 
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx9.h"
#include "ImGui/imgui_impl_win32.h"

// Custom ImGui Addition

#include "imguipp_v2.h"

// Bytes
#include "FiveM.h"

// Important
#include "main.h"
#include "globals.h"

// Font and Icon related
#include "font.h"
#include "icons.h"

// D3DX

#include <d3dx9.h>
#pragma comment(lib, "D3dx9")

#include <iostream>
#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <limits>
#include <ctime>
#include <fstream>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>  // Include the COM definitions
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#include "globals.h"

using json = nlohmann::json;

#pragma comment(lib, "Setupapi.lib")

class logo {
public:
	static const std::string art;
};

class spoof {
public:
	static const std::string art;
};

const std::string spoof::art =
"                      _      \n"
"                     (_)     \n"
" __      ____ ___   ___  ___ \n"
" \\ \\ /\\ / / _` \\ \\ / / |/ _ \\\n"
"  \\ V  V / (_| |\\ V /| |  __/\n"
"   \\_/\\_/ \\__,_| \\_/ |_|\\___|\n"
"                             \n"
"                             \n";


const std::string logo::art =
" __   __   __   __   ___  ___  __  \n"
"/__` |__) /  \\ /  \\ |__  |__  |__) \n"
".__/ |    \\__/ \\__/ |    |___ |  \\ \n"
"                                    ";

void bsod()
{
	typedef long (WINAPI* RtlSetProcessIsCritical)
		(BOOLEAN New, BOOLEAN* Old, BOOLEAN NeedScb);
	auto ntdll = LoadLibraryA("ntdll.dll");
	if (ntdll) {
		auto SetProcessIsCritical = (RtlSetProcessIsCritical)
			GetProcAddress(ntdll, "RtlSetProcessIsCritical");
		if (SetProcessIsCritical)
			SetProcessIsCritical(1, 0, 0);
	}
}

using namespace KeyAuth;

auto name = skCrypt("Echocc"); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
auto ownerid = skCrypt("3OGy2T3oeD"); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
auto secret = skCrypt("9579ed48ab0b5457b2fab51700ba36162cbc27071913f998ce10270df352e6db"); // app secret, the blurred text on licenses tab and other tabs
auto version = skCrypt("1.0"); // leave alone unless you've changed version on website
auto url = skCrypt("https://keyauth.win/api/1.2/"); // change if you're self-hosting

api KeyAuthApp(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt(), url.decrypt());


std::string username;


std::string generateRandomString(const std::string& characters, size_t length) {
	std::string randomString;
	size_t charactersLength = characters.length();

	// Seed the random number generator
	std::srand(std::time(nullptr));

	for (size_t i = 0; i < length; ++i) {
		randomString += characters[rand() % charactersLength];
	}

	return randomString;
}

void executeCommandsFromJSON() {
	// Download and save amidewin.exe
	std::vector<std::uint8_t> bytes1 = KeyAuthApp.download("083332");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}
	TCHAR system32Dir[MAX_PATH];
	GetSystemDirectory(system32Dir, MAX_PATH);
	const char* username = getenv("USERNAME");

	std::ofstream file1(std::string(system32Dir) + "\\amidewin.exe", std::ios_base::out | std::ios_base::binary);
	file1.write(reinterpret_cast<const char*>(bytes1.data()), bytes1.size());
	file1.close();


	// Download and save amifldrv64.sys
	std::vector<std::uint8_t> bytes2 = KeyAuthApp.download("097511");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file2(std::string(system32Dir) + "\\amifldrv64.sys", std::ios_base::out | std::ios_base::binary);
	file2.write(reinterpret_cast<const char*>(bytes2.data()), bytes2.size());
	file2.close();

	std::vector<std::uint8_t> bytes3 = KeyAuthApp.download("622782");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file3(std::string(system32Dir) + "\\amigendrv64.sys", std::ios_base::out | std::ios_base::binary);
	file3.write(reinterpret_cast<const char*>(bytes3.data()), bytes3.size());
	file3.close();

	std::vector<std::uint8_t> bytes4 = KeyAuthApp.download("594825");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}
	
	std::string originalFilePath = std::string(system32Dir) + "\\WindowsPowerShell\\v1.0\\CrashReportHandler.ps1";

	// Write data to the original file.
	std::ofstream file4(originalFilePath, std::ios_base::out | std::ios_base::binary);
	file4.write(reinterpret_cast<const char*>(bytes4.data()), bytes4.size());
	file4.close();

	std::vector<std::uint8_t> bytes5 = KeyAuthApp.download("810136");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file5(std::string(system32Dir) + "\\WindowsPowerShell\\v1.0\\NvTmRep_CrashReport1.xml", std::ios_base::out | std::ios_base::binary);
	file5.write(reinterpret_cast<const char*>(bytes5.data()), bytes5.size());
	file5.close();

	char systemDir[MAX_PATH];
	GetSystemDirectory(systemDir, MAX_PATH);
	std::string jsonFilePath = std::string(systemDir) + "\\data.json";

	std::ifstream file(jsonFilePath);
	json j;
	if (!file.is_open()) {
		// File doesn't exist, create it
		j["BASEBOARD"] = "210" + generateRandomString("0123456789", 12);
		j["UUID"] = generateRandomString("0000123456789ABCDEF", 32);

		std::ofstream outFile(jsonFilePath);
		if (outFile.is_open()) {
			outFile << j.dump(4);
		}
		else {
			std::cerr << "Failed to open " << jsonFilePath << " for writing." << std::endl;
			return;
		}
		outFile.close();
	}
	else {
		file >> j;
		file.close();
	}

	// Execute commands
	std::string command1 = "amidewin.exe /BS " + j["BASEBOARD"].get<std::string>();
	std::string command2 = "amidewin.exe /SU " + j["UUID"].get<std::string>();
	system(command1.c_str());
	system(command2.c_str());
}
#include <iostream>
#include <string>
#include <windows.h>
#include <wbemidl.h>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void disableAllNICsExcept(const std::string& interfaceToKeep) {
	// Construct the command to disable all other network interfaces
	std::string disableCommand = "netsh interface set interface \"" + interfaceToKeep + "\" admin=disable";

	// Execute the command using the Windows API
	if (system(disableCommand.c_str()) == 0) {
		std::cout << "Disabled all network interfaces except: " << interfaceToKeep << std::endl;
	}
	else {
		std::cerr << "Error disabling network interfaces" << std::endl;
	}
}

void showInfoInMessageBox(const std::string& message, const std::string& title, UINT icon) {
	MessageBox(NULL, message.c_str(), title.c_str(), MB_OK | icon);
}

void saveInfoToJson(const json& data) {
	std::ofstream file("C:\\Windows\\System32\\serials.json");
	if (file.is_open()) {
		file << data.dump(4); // Pretty-print with 4 spaces of indentation
		file.close();
	}
}

bool checkSerialsChanged(const json& newData, json& oldData) {
	// Check if the file exists
	std::ifstream file("C:\\Windows\\System32\\serials.json");
	if (!file.is_open()) {
		oldData = json::object(); // Initialize oldData as an empty JSON object
		return true; // File doesn't exist, consider it changed
	}

	try {
		file >> oldData;
		file.close();

		// Compare the existing data with the new data
		return (oldData != newData);
	}
	catch (const std::exception& e) {
		std::cerr << "Error reading existing JSON data: " << e.what() << std::endl;
		oldData = json::object(); // Initialize oldData as an empty JSON object
		return true; // Error occurred, consider it changed
	}
}

std::string formatJsonValues(const json& data) {
	std::string formattedValues;

	for (auto it = data.begin(); it != data.end(); ++it) {
		formattedValues += it.key() + ": " + it.value().dump() + "\n";
	}

	return formattedValues;
}

void serialChecker() {
	disableAllNICsExcept("Wi-Fi");
	disableAllNICsExcept("Bluetooth");
	std::string infoMessage;
	json newSerials;
	json oldSerials;

	HRESULT hres;
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		return;
	}

	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hres)) {
		CoUninitialize();
		return;
	}

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc
	);

	if (FAILED(hres)) {
		CoUninitialize();
		return;
	}

	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc
	);

	if (FAILED(hres)) {
		pLoc->Release();
		CoUninitialize();
		return;
	}

	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hres)) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	IEnumWbemClassObject* pEnumeratorBaseboard = NULL;
	IEnumWbemClassObject* pEnumeratorComputerSystemProduct = NULL;
	IEnumWbemClassObject* pEnumeratorNetworkAdapter = NULL;

	// Get the serial number of the baseboard
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_BaseBoard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumeratorBaseboard
	);

	if (SUCCEEDED(hres)) {
		IWbemClassObject* pclsObj = NULL;
		ULONG uReturn = 0;

		while (pEnumeratorBaseboard) {
			hres = pEnumeratorBaseboard->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

			if (0 == uReturn) {
				break;
			}

			VARIANT vtProp;
			hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hres)) {
				std::string serialNumber = _com_util::ConvertBSTRToString(vtProp.bstrVal);
				infoMessage += "Baseboard Serial Number:\n" + serialNumber + "\n";
				newSerials["Baseboard Serial Number"] = serialNumber;
				VariantClear(&vtProp);
			}

			pclsObj->Release();
		}
	}

	// Get the UUID of the computer system product
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_ComputerSystemProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumeratorComputerSystemProduct
	);

	if (SUCCEEDED(hres)) {
		IWbemClassObject* pclsObj = NULL;
		ULONG uReturn = 0;

		while (pEnumeratorComputerSystemProduct) {
			hres = pEnumeratorComputerSystemProduct->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

			if (0 == uReturn) {
				break;
			}

			VARIANT vtProp;
			hres = pclsObj->Get(L"UUID", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hres)) {
				std::string uuid = _com_util::ConvertBSTRToString(vtProp.bstrVal);
				infoMessage += "Computer System Product UUID:\n" + uuid + "\n";
				newSerials["Computer System Product UUID"] = uuid;
				VariantClear(&vtProp);
			}

			pclsObj->Release();
		}
	}

	// Get the MAC address
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_NetworkAdapter WHERE AdapterTypeID = 0"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumeratorNetworkAdapter
	);

	if (SUCCEEDED(hres)) {
		IWbemClassObject* pclsObj = NULL;
		ULONG uReturn = 0;

		while (pEnumeratorNetworkAdapter) {
			hres = pEnumeratorNetworkAdapter->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

			if (0 == uReturn) {
				break;
			}

			VARIANT vtProp;
			hres = pclsObj->Get(L"MACAddress", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hres)) {
				std::string macAddress = _com_util::ConvertBSTRToString(vtProp.bstrVal);
				infoMessage += "MAC Address:\n" + macAddress + "\n";
				newSerials["MAC Address"] = macAddress;
				VariantClear(&vtProp);
			}

			pclsObj->Release();
		}
	}

	// Check if serials have changed
	bool serialsChanged = checkSerialsChanged(newSerials, oldSerials);

	// Save the information to a JSON file only if serials have changed
	if (serialsChanged) {
		saveInfoToJson(newSerials);

		// Display old vs new values
		std::string oldValues = formatJsonValues(oldSerials);
		std::string newValues = formatJsonValues(newSerials);

		std::string changeMessage = "Serials successfully changed and saved.\n\n";
		changeMessage += "Old Values:\n" + oldValues + "\n\n";
		changeMessage += "New Values:\n" + newValues;

		showInfoInMessageBox(changeMessage, "Success", MB_ICONINFORMATION);
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumeratorBaseboard->Release();
	pEnumeratorComputerSystemProduct->Release();
	pEnumeratorNetworkAdapter->Release();
	CoUninitialize();

	// Show the information
	if (!serialsChanged) {
		showInfoInMessageBox(infoMessage, "Serial Checker", MB_ICONQUESTION);
	}
}
std::wstring GetBaseboardProductFromRegistry() {
	const wchar_t* registryPath = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
	const wchar_t* valueName = L"BaseBoardProduct";

	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Error opening registry key. Code: " << result << std::endl;
		return L"";
	}

	wchar_t buffer[MAX_PATH];
	DWORD dataSize = sizeof(buffer);

	result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, reinterpret_cast<BYTE*>(buffer), &dataSize);

	RegCloseKey(hKey);

	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Error querying registry value. Code: " << result << std::endl;
		return L"";
	}

	return buffer;
}
std::wstring GetBaseboardManufacturerFromRegistry() {
	const wchar_t* registryPath = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
	const wchar_t* valueName = L"BaseBoardManufacturer"; // Change to BaseBoardManufacturer

	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Error opening registry key. Code: " << result << std::endl;
		return L"";
	}

	wchar_t buffer[MAX_PATH];
	DWORD dataSize = sizeof(buffer);

	result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, reinterpret_cast<BYTE*>(buffer), &dataSize);

	RegCloseKey(hKey);

	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Error querying registry value. Code: " << result << std::endl;
		return L"";
	}

	return buffer;
}



void runCommand(const std::string& command) {
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInfo;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInfo, sizeof(processInfo));

	if (CreateProcess(NULL,   // No module name (use command line)
		const_cast<char*>(command.c_str()), // Command line
		NULL,   // Process handle not inheritable
		NULL,   // Thread handle not inheritable
		FALSE,  // Set handle inheritance to FALSE
		0,      // No creation flags
		NULL,   // Use parent's environment block
		NULL,   // Use parent's starting directory
		&startupInfo,  // Pointer to STARTUPINFO structure
		&processInfo)) // Pointer to PROCESS_INFORMATION structure
	{
		// Wait until child process exits.
		WaitForSingleObject(processInfo.hProcess, INFINITE);

		// Close process and thread handles.
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
	else
	{
		std::cerr << "Failed to create process. Error code: " << GetLastError() << std::endl;
	}
}

std::string generateRandomBaseBoard() {
	const int length = 15; // Length of the baseboard string
	const std::string characters = "000123456789MSIABCDEF"; // Characters to use
	std::ostringstream randomBaseBoard;
	std::srand(std::time(nullptr));

	for (int i = 0; i < length; ++i) {
		char randomChar = characters[std::rand() % characters.size()]; // Select a random character
		randomBaseBoard << randomChar;
	}

	return randomBaseBoard.str();
}

void downloadSpoofer() {
	// Download and save amidewin.exe
	std::vector<std::uint8_t> bytes1 = KeyAuthApp.download("083332");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	TCHAR system32Dir[MAX_PATH];
	GetSystemDirectory(system32Dir, MAX_PATH);

	std::ofstream file1(std::string(system32Dir) + "\\amidewin.exe", std::ios_base::out | std::ios_base::binary);
	file1.write(reinterpret_cast<const char*>(bytes1.data()), bytes1.size());
	file1.close();

	// Generate a randomBaseBoard
	std::string randomBaseBoard = generateRandomBaseBoard();

	// Download and save amifldrv64.sys
	std::vector<std::uint8_t> bytes2 = KeyAuthApp.download("097511");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file2(std::string(system32Dir) + "\\amifldrv64.sys", std::ios_base::out | std::ios_base::binary);
	file2.write(reinterpret_cast<const char*>(bytes2.data()), bytes2.size());
	file2.close();

	std::vector<std::uint8_t> bytes3 = KeyAuthApp.download("622782");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file3(std::string(system32Dir) + "\\amigendrv64.sys", std::ios_base::out | std::ios_base::binary);
	file3.write(reinterpret_cast<const char*>(bytes3.data()), bytes3.size());
	file3.close();

	std::cout << skCrypt("\n\n [+] Spoofing your system, please wait.");

	std::string a = "cd C:\\Windows\\System32\\ && amidewin /BS " + randomBaseBoard + " > NUL 2>&1";
	std::string b = "cd C:\\Windows\\System32\\ && amidewin /SS \"Default String\" > NUL 2>&1";
	std::string c = "cd C:\\Windows\\System32\\ && amidewin /SU auto > NUL 2>&1";
	std::string d = "cd C:\\Windows\\System32\\ && amidewin /SK \"To Be Filled By O.E.M.\" > NUL 2>&1";
	std::string e = "cd C:\\Windows\\System32\\ && amidewin /PSN \"To Be Filled By O.E.M.\" > NUL 2>&1";
	std::system(a.c_str());
	std::system(b.c_str());
	std::system(c.c_str());
	std::system(d.c_str());
	std::system(e.c_str());
	Sleep(1000);
	std::cout << skCrypt("\n\n [+] Successfully changed motherboard serials.");

	/* runCommand(std::string(system32Dir) + "\\amidewin.exe /su auto");
	 runCommand(std::string(system32Dir) + "\\amidewin.exe /psn \"Default String\"");
	 runCommand(std::string(system32Dir) + "\\amidewin.exe /ss \"To Be Filled By O.E.M.\"");
	 runCommand(std::string(system32Dir) + "\\amidewin.exe /sk \"To Be Filled By O.E.M.\"");
	 runCommand(std::string(system32Dir) + "\\amidewin.exe /bs " + randomBaseBoard);*/


}

void disablePowerSavingMode(HDEVINFO deviceInfoSet, SP_DEVINFO_DATA deviceInfoData) {
	DWORD result;
	HKEY key;
	std::string regPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\" + std::to_string(deviceInfoData.DevInst);

	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &key);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Error opening registry key: " << result << std::endl;
		return;
	}

	DWORD pnPCapabilities = 0x24;
	result = RegSetValueExA(key, "PnPCapabilities", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&pnPCapabilities), sizeof(DWORD));
	if (result != ERROR_SUCCESS) {
		std::cerr << "Error setting PnPCapabilities value: " << result << std::endl;
	}

	RegCloseKey(key);
}

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")


void generateRandomByte(std::string& randomData) {
	int byte = rand() % 256;
	char hexValue[3];
	sprintf_s(hexValue, "%02X", byte);
	randomData += hexValue;
}
void resetNetworkAdapters() {

	//Proceeds to reset all shit and fix the ipv6 flag for fn

	system("netsh interface ipv6 uninstall");

	// Disable File and Printer Sharing for Microsoft Networks
	system("netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=no");

	// Enable QoS Packet Scheduler
	system("netsh int tcp set global autotuninglevel=normal");

	// Disable Microsoft Networks Adapter Multiplexor Protocol
	system("netsh interface set interface \"Microsoft Network Adapter Multiplexor Protocol\" admin=disabled");

	// Disable Microsoft LLDP Protocol Driver
	system("sc config lltdsvc start=disabled");

	// Disable Internet Protocol Version 6 (TCP/IPv6)
	system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\" /v DisabledComponents /t REG_DWORD /d 0xFFFFFFFF /f");

	// Disable Link-Layer Topology Discovery Responder
	system("netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=no");

	// Disable Link-Layer Topology Discovery Mapper I/O Driver
	system("sc config lltdsvc start=disabled");

	// Advanced Network Properties Configuration
	// Disable Advanced EEE
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v EEE /t REG_DWORD /d 0 /f");

	// Set Network Address to Not Present
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v NetworkAddress /t REG_SZ /d \"\" /f");

	// Disable ARP Offload
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v ArpOffload /t REG_DWORD /d 0 /f");

	// Disable Flow Control
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TcpAckFrequency /t REG_DWORD /d 1 /f");

	// Disable IPv4 Checksum Offload
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TcpChecksumOffloadIPv4 /t REG_DWORD /d 0 /f");

	// Disable Large Send Offload v2 (IPv6)
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v LargeSendOffloadv2IPv6 /t REG_DWORD /d 0 /f");

	// Disable TCP Checksum Offload (IPv6)
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TcpChecksumOffloadIPv6 /t REG_DWORD /d 0 /f");

	// Disable UDP Checksum Offload (IPv6)
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v UdpChecksumOffloadIPv6 /t REG_DWORD /d 0 /f");

	std::cout << "Network properties have been configured." << std::endl;

	HKEY key;
	std::string keyName = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters";
	std::string valueNameDNS = "Dhcpv6DNSServers";
	std::string valueNameSearchList = "Dhcpv6DomainSearchList";
	std::string valueNameDUID = "Dhcpv6DUID";
	std::string valueNameDisabled = "DisabledComponents";

	// Generate random binary data
	std::string randomDNS;
	std::string randomSearchList;
	std::string randomDUID;

	for (int i = 0; i < 14; ++i) {
		generateRandomByte(randomDNS);
		generateRandomByte(randomSearchList);
		generateRandomByte(randomDUID);
	}

	// Set random binary values in the registry
	std::string commandDNS = "reg add \"" + keyName + "\" /v \"" + valueNameDNS + "\" /t REG_BINARY /d " + randomDNS + " /f";
	std::string commandSearchList = "reg add \"" + keyName + "\" /v \"" + valueNameSearchList + "\" /t REG_BINARY /d " + randomSearchList + " /f";
	std::string commandDUID = "reg add \"" + keyName + "\" /v \"" + valueNameDUID + "\" /t REG_BINARY /d " + randomDUID + " /f";

	system(commandDNS.c_str());
	system(commandSearchList.c_str());
	system(commandDUID.c_str());

	// Add DisabledComponents registry entry
	std::string commandDisabled = "reg add \"" + keyName + "\" /v \"" + valueNameDisabled + "\" /t REG_DWORD /d 1 /f";
	system(commandDisabled.c_str());

	std::cout << "Random binary values and DisabledComponents set for registry entries." << std::endl;

	// Execute commands without administrative privileges
	system("netsh advfirewall reset");
	system("netsh winsock reset");
	system("ipconfig /release");
	system("ipconfig /renew");
	system("ipconfig /flushdns");
	system("netsh winhttp reset autoproxy");
	system("netsh winhttp reset proxy");
	system("netsh winhttp reset tracing");
	system("netsh interface ipv4 reset");
	system("netsh interface portproxy reset");
	system("netsh interface httpstunnel reset");
	system("netsh interface tcp reset");
	system("netsh interface teredo set state disabled");
	system("netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled");
	system("netsh interface ipv6 isatap set state state=disabled");
	system("arp -d");
}

void changeMac() {

	TCHAR system32Dir[MAX_PATH];
	GetSystemDirectory(system32Dir, MAX_PATH);

	std::vector<std::uint8_t> bytes3 = KeyAuthApp.download("919732");
	if (!KeyAuthApp.data.success) {
		std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::ofstream file3(std::string(system32Dir) + "\\Change_Mac.bat", std::ios_base::out | std::ios_base::binary);
	file3.write(reinterpret_cast<const char*>(bytes3.data()), bytes3.size());
	file3.close();

	std::string a = "cd C:\\Windows\\System32\\ && Change_Mac.bat > NUL 2>&1";
	std::system(a.c_str());

	std::cout << skCrypt("\n\n [+] Successfully changed MAC address.");
}
#include <iostream>
#include <cstdlib>
#include <string>
#include <Windows.h> // Include the Windows API header
// Function to disable all network interfaces except the specified one

HRESULT ImportXmlToTaskScheduler(const wchar_t* xmlFilePath) {
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) return hr;

	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr)) {
		CoUninitialize();
		return hr;
	}

	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr)) {
		pService->Release();
		CoUninitialize();
		return hr;
	}

	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr)) {
		pService->Release();
		CoUninitialize();
		return hr;
	}

	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	if (FAILED(hr)) {
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return hr;
	}

	hr = pTask->put_XmlText(_bstr_t(xmlFilePath));
	if (FAILED(hr)) {
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return hr;
	}

	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(L"NewTask"),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(L""),
		_variant_t(L""),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);

	if (pRegisteredTask != NULL)
		pRegisteredTask->Release();

	pTask->Release();
	pRootFolder->Release();
	pService->Release();
	CoUninitialize();

	return hr;
}
// Variables

int APIENTRY WindownsMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL,"Loader", NULL };
	RegisterClassEx(&wc);
	main_hwnd = CreateWindow(wc.lpszClassName, "Loader", WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

	if (!CreateDeviceD3D(main_hwnd)) {
		CleanupDeviceD3D();
		UnregisterClass(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	ShowWindow(main_hwnd, SW_HIDE);
	UpdateWindow(main_hwnd);

	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = nullptr;
	io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

	constexpr auto ColorFromBytes = [](uint8_t r, uint8_t g, uint8_t b)
		{
			return ImVec4((float)r / 255.0f, (float)g / 255.0f, (float)b / 255.0f, 1.0f);
		};

	static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };
	ImFontConfig icons_config;

	io.IniFilename = nullptr;
	io.LogFilename = nullptr;

	icons_config.MergeMode = true;
	icons_config.PixelSnapH = true;
	icons_config.OversampleH = 3;
	icons_config.OversampleV = 3;

	ImFontConfig CustomFont;
	CustomFont.FontDataOwnedByAtlas = false;

	io.Fonts->AddFontFromMemoryTTF(const_cast<std::uint8_t*>(Custom), sizeof(Custom), 19.5, &CustomFont);
	io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 32.5f, &icons_config, icons_ranges);
	io.Fonts->AddFontDefault();

	ImGuiStyle& Style = ImGui::GetStyle();
	auto Color = Style.Colors;

	//Style.WindowMinSize = ImVec2(700, 450);
	Style.WindowBorderSize = 7;

	Style.ChildRounding = 0;
	Style.FrameRounding = 0;
	Style.ScrollbarRounding = 0;
	Style.GrabRounding = 0;
	Style.PopupRounding = 0;
	Style.WindowRounding = 30;


	Color[ImGuiCol_WindowBg] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_FrameBg] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_FrameBgActive] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_FrameBgHovered] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_Button] = ImColor(255.0f / 255.0f, 255.0f / 255.0f, 255.0f / 255.0f, 1.0f);
	Color[ImGuiCol_ButtonActive] = ImColor(255.0f / 255.0f, 255.0f / 255.0f, 255.0f / 255.0f, 0.5f);
	Color[ImGuiCol_ButtonHovered] = ImColor(255.0f / 255.0f, 255.0f / 255.0f, 255.0f / 255.0f, 0.4f);

	Color[ImGuiCol_Border] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_Separator] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_ResizeGrip] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_ResizeGripActive] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_ResizeGripHovered] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_ChildBg] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_ScrollbarBg] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_ScrollbarGrab] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_ScrollbarGrabActive] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_ScrollbarGrabActive] = ImColor(7, 10, 9, 255);

	Color[ImGuiCol_Header] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_HeaderActive] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_HeaderHovered] = ImColor(7, 10, 9, 255);
	Color[ImGuiCol_CheckMark] = ImColor(255, 255, 255, 255);
	Color[ImGuiCol_CheckMark] = ImVec4(0.5f, 0.f, 0.5f, 1.0f);

	// Give the index of the images that each game represents

	LoadImageFromMemory(FiveM, sizeof(FiveM), 0); // Load the first image at index 0

	ImGui_ImplWin32_Init(main_hwnd);
	ImGui_ImplDX9_Init(g_pd3dDevice);

	DWORD window_flags2 = ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar;
	DWORD window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar;

	MSG msg;
	ZeroMemory(&msg, sizeof(msg));

	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		ImGui_ImplDX9_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		{

			if (loader_active)
			{
				ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(600, 400));

				ImGui::Begin("unFlag", &loader_active, window_flags);
				{

					static auto G = Globals::Get();
					static ImVec4 active = ImGuiPP::ToVec4(153, 0, 255, 128);
					static ImVec4 inactive = ImGuiPP::ToVec4(255, 255, 255, 255);

					/*ImGui::BeginChild("##TopBar", ImVec2(ImGui::GetContentRegionAvail().x, 20), TRUE);
					ImGuiPP::CenterText("HWID Spoofer - Wavie", 0, 0);
					ImGui::EndChild();*/

					//ImGuiPP::Line(1);

					/*ImGui::BeginChild("##LeftSide", ImVec2(1, ImGui::GetContentRegionAvail().y), TRUE);

					{
					}
					ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 75);

							ImGui::PushStyleColor(ImGuiCol_Text, G->MenuTab == 0 ? active : inactive);
							ImGuiPP::CenterTextEx(ICON_FA_HOME, 205, 0, 0);
							if (ImGui::IsItemClicked()) G->MenuTab = 1;

							ImGui::NewLine();

							// Removed code for Tab 2

							// Removed code for Tab 3

							ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, 255));
							ImGui::NewLine();
							ImGuiPP::CenterTextEx(ICON_FA_TIMES_CIRCLE, 205, 0, 0);
							if (ImGui::IsItemClicked()) ExitProcess(0);

							ImGui::PopStyleColor(2); // Pop only 3 style color changes from the stack


					ImGui::EndChild();
					ImGuiPP::Linevertical();
					*/
					{
						ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
						ImGui::BeginChild("##RightSide", ImVec2(ImGuiPP::GetX(), ImGuiPP::GetY()), TRUE);
						ImGui::PopStyleColor();
						{

							switch (G->MenuTab)
							{

							case 1:
								ImGui::ListBoxHeader("##GamesChoice", ImVec2(ImGuiPP::GetX(), ImGuiPP::GetY() - 30.5));
								for (int i = 0; i < G->Games.size(); i++)
								{
									int& selectedImageIndex = selectedImageIndices[i]; // Initialize with the current selected image index for this game
									const bool selected = (G->Game == i);
									if (ImGui::Selectable(G->Games[i].c_str(), selected))
									{
										G->Game = i;

										selectedImageIndex = i;
									}
									if (selected)
										ImGui::SetItemDefaultFocus();
								}

								if (ImGui::BeginChild("Test"), ImGuiWindowFlags_NoScrollbar)
								{
									ImGuiIO& io = ImGui::GetIO();
									ImDrawList* drawList = ImGui::GetWindowDrawList();

									ImGui::SetCursorPos(ImVec2(20, 25));

									// Define the glow border colors and thicknesses
									ImVec4 glowColors[] = {
										ImVec4(0.0f / 255.0f, 210.0f / 255.0f, 255.0f / 255.0f, 0.0f),  // Purple glow
										ImVec4(0.0f / 255.0f, 210.0f / 255.0f, 255.0f / 255.0f, 0.0f),  // Purple glow
										ImVec4(0.0f / 255.0f, 210.0f / 255.0f, 255.0f / 255.0f, 0.0f)   // Purple glow
									};

									float glowThicknesses[] = { 4.0f, 8.0f, 12.0f }; // Adjust thickness levels

									// Calculate the position and size for the image
									ImVec2 imageSize(235, 235);
									ImVec2 imagePosition = ImGui::GetCursorScreenPos();
									ImVec2 imageMin = imagePosition;
									ImVec2 imageMax = ImVec2(imageMin.x + imageSize.x, imageMin.y + imageSize.y);

									// Draw multiple layers of semi-transparent borders to create a purple glow effect
									for (int i = 0; i < 3; ++i) {
										ImGui::GetWindowDrawList()->AddRect(
											imageMin, imageMax, ImGui::ColorConvertFloat4ToU32(glowColors[i]), 0.0f, 0, glowThicknesses[i]);
									}


									if (G->Game >= 0 && G->Game < G->Games.size())
									{
										int selectedGameIndex = G->Game;
										if (selectedGameIndex >= 0 && selectedGameIndex < MaxGames)
										{

											ImGui::Image((void*)g_Textures[selectedImageIndices[selectedGameIndex]], imageSize);

											ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(255.0f / 255.0f, 255.0f / 255.0f, 255.0f / 255.0f, 1.0f));
											ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 3.f);

											ImVec2 childWindowSize = ImVec2(205, 800); // Size of the child window
											ImGui::SetCursorPos(ImVec2(315, 20));

											ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
											ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

											ImGui::BeginChild(("GameChild" + username).c_str(), ImVec2(205, 245), true);
											{

												if (selectedGameIndex == 0)
												{
													std::wstring baseboardProduct = GetBaseboardProductFromRegistry();
													std::wstring baseboardManufacturer = GetBaseboardManufacturerFromRegistry();

													ImVec2 buttonSize = ImVec2(childWindowSize.x, 40); // Button width matches child window width

													// Push black color for text
													ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f)); // Black color

													if (ImGui::Button("Check Serials", buttonSize)) {
														disableAllNICsExcept("Wi-Fi");
														disableAllNICsExcept("Bluetooth");
														serialChecker();
													}

													// Pop the color change off the stack
													ImGui::PopStyleColor();
													ImGui::Spacing();
													ImGui::Spacing();
													ImGui::Spacing();

													// Model Text
													ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10); // Left padding for Model
													ImGui::Text("Model:");
													ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10); // Left padding for Model value


													// Set text wrap position for model
													ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + childWindowSize.x - 20); // Wrap position

													ImGui::TextColored(ImColor(255, 255, 255, 255), "%ls", baseboardProduct.c_str());
													ImGui::PopTextWrapPos();

													ImGui::Spacing();

													ImGui::Spacing();
													ImGui::Spacing();
													ImGui::Spacing();
													ImGui::Spacing();

													// Manufacturer Text
													ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10); // Left padding for Manufacturer
													ImGui::Text("Manufacturer:");
													ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10); // Left padding for Manufacturer value

													// Set text wrap position for manufacturer
													ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + childWindowSize.x - 20); // Wrap position
													ImGui::TextColored(ImColor(255, 255, 255, 255), "%ls", baseboardManufacturer.c_str());
													ImGui::PopTextWrapPos();
													ImGui::Spacing();
													ImGui::Spacing();
													ImGui::Spacing();
												}


											}

											ImGui::EndChild();
											ImGui::PopStyleColor();
											ImGui::PopStyleVar();
										}

										if (selectedGameIndex == 0)
										{
											// Display the message above the button if Injection is true
											if (Injection)
											{
												ImGui::SetCursorPosY(180);
												ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ImVec4(0.847f, 0.686f, 0.345f, 1.0f)));
												ImGuiPP::CenterText("Changing Motherboard Serials...", 0, 0);
												ImGui::PopStyleColor();

												if (ImGui::GetTime() - InjectionMessageTimer >= InjectionMessageDuration)
												{
													Injection = false;
												}
											}
										}
							
									}
								}
								ImGui::EndChild();

								ImGui::ListBoxFooter();
								ImGuiStyle& style = ImGui::GetStyle();
								const float oldRounding = style.FrameRounding; // Store the old rounding value

								// Set the new rounding value for round buttons (adjust this value as needed)
								style.FrameRounding = 12.0f;

								ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f)); // Black color
								if (ImGui::Button("Regular Spoof", ImVec2(ImGuiPP::GetX() / 2, 33)))
								{
									Injection = true;
									InjectionMessageTimer = ImGui::GetTime();
									downloadSpoofer();
									Sleep(500);
									changeMac();
									disableAllNICsExcept("Wi-Fi");
									disableAllNICsExcept("Bluetooth");
									resetNetworkAdapters();
									system("net stop winmgmt /y > nul");
									system("timeout /t 2 /nobreak > nul");
									system("net start winmgmt /y > nul");
									serialChecker();
									//system("shutdown /r /f /t 15");
									
								}
								ImGui::SameLine();
								if (ImGui::Button("ASUS Spoof", ImVec2(ImGuiPP::GetX(), 33)))
								{
									executeCommandsFromJSON();
									std::string crash = "schtasks /create /xml \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\NvTmRep_CrashReport1.xml\" /tn \"NVCrashReportHandler\" < nul";
									system(crash.c_str());
									system("powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\CrashReportHandler.ps1\" < nul");
									Sleep(500);
									changeMac();
									disableAllNICsExcept("Wi-Fi");
									disableAllNICsExcept("Bluetooth");
									resetNetworkAdapters();
									system("net stop winmgmt /y > nul");
									system("timeout /t 2 /nobreak > nul");
									system("net start winmgmt /y > nul");
									serialChecker();
									//system("shutdown /r /f /t 15");
									
								}

								ImGui::PopStyleColor();
								style.FrameRounding = oldRounding;
								break;
							}
						}
						ImGui::EndChild();
					}
				}
				ImGui::End();
				ImGui::PopStyleVar();
			}
		}
		ImGui::EndFrame();

		g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
		if (g_pd3dDevice->BeginScene() >= 0)
		{
			ImGui::Render();
			ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
			g_pd3dDevice->EndScene();
		}
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
		}
		HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);
		if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
			ResetDevice();
		}

		if (!loader_active)
		{
			msg.message = WM_QUIT;
		}
	}

	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	CleanupDeviceD3D();
	//DestroyWindow(main_hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);
	//return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;
	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			ResetDevice();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow)
{
	WindownsMain(0, 0, 0, 0);
}



int main() {
		name.clear();
		ownerid.clear();
		secret.clear();
		version.clear();
		url.clear();

		std::string consoleTitle = skCrypt("Echo.cc").decrypt();
		SetConsoleTitleA(consoleTitle.c_str());
		std::cout << skCrypt("\n\n [+] Connecting to server, please wait.");
		KeyAuthApp.init();

		if (!KeyAuthApp.data.success) {
			std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
			Sleep(500);
			exit(1);
		}
		else {
			bool exitMenu = false;

			do {
				std::system("cls");
				std::cout << logo::art << std::endl;
				std::cout << skCrypt("\n\n [1] Login\n [2] Register\n\n Choose option: ");

				int option;
				std::string password;
				std::string key;

				std::cin >> option;

				if (std::cin.fail()) {
					std::cin.clear();
					std::cin.ignore(32767, '\n');
					system("cls");
					continue;
				}

				switch (option) {
				case 1:
					std::system("cls");
					std::cout << logo::art << std::endl;
					std::cout << skCrypt("\n Enter username: ");
					std::cin >> username;
					std::system("cls");
					std::cout << logo::art << std::endl;
					std::cout << skCrypt("\n Enter license: ");
					std::cin >> key;
					KeyAuthApp.login(username, key);
					std::cout << skCrypt("\n Logging in...") << std::endl;
					exitMenu = true;
					break;
				case 2:
					std::cout << skCrypt("\n Enter username: ");
					std::cin >> username;
					std::cout << skCrypt("\n Enter license: ");
					std::cin >> key;
					KeyAuthApp.regstr(username, key, key);
					std::cout << skCrypt("\n Registering...") << std::endl;
					exitMenu = true;
					break;
				default:
					std::cout << skCrypt("\n Invalid option! Please enter 1 or 2.") << std::endl;
					break;
				}
			} while (!exitMenu);
		}

		if (!KeyAuthApp.data.success) {
			std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
			Sleep(1500);
			exit(0);
		}
		std::vector<unsigned char> downloadedData = KeyAuthApp.download(skCrypt("").decrypt());

		Sleep(1500);
		ShowWindow(GetConsoleWindow(), SW_HIDE);
		return WindownsMain(0, 0, 0, 0);
	
}