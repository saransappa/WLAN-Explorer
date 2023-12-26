#ifndef UNICODE
#define UNICODE
#endif
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wlanapi.h>
#include <Windot11.h>           // for DOT11_SSID struct
#include <objbase.h>
#include <wtypes.h>
#include <iphlpapi.h>

//#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <cwctype>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <thread>
#include <chrono>

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")


using namespace std;


void printDot11MacAddress(const DOT11_MAC_ADDRESS& macAddress) {
    for (int i = 0; i < 6; ++i) {
        printf("%02X", macAddress[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\n");
}

string ConvertDot11MacAddressToString(const DOT11_MAC_ADDRESS& macAddress) {
    ostringstream macStream;
    macStream << hex << setfill('0');

    for (int i = 0; i < 6; ++i) {
        macStream << setw(2) << static_cast<unsigned>(macAddress[i]);
        if (i < 5) {
            macStream << ":";
        }
    }

    return macStream.str();
}

wstring ConvertUcharToWstring(const UCHAR* ucharString, UINT codePage= CP_ACP) {
    int requiredSize = MultiByteToWideChar(codePage, 0, reinterpret_cast<LPCCH>(ucharString), -1, NULL, 0);

    if (requiredSize > 0) {
        wstring convertedString(requiredSize-1, L'\0');
        MultiByteToWideChar(codePage, 0, reinterpret_cast<LPCCH>(ucharString), -1, &convertedString[0], requiredSize);
        return convertedString;
    }

    // Handle error (return an empty string or throw an exception)
    return L"";
}

UCHAR* ConvertWstringToUCHAR(const std::wstring& wstr) {
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);

    if (bufferSize > 0) {
        UCHAR* buffer = new UCHAR[bufferSize];
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, reinterpret_cast<LPSTR>(buffer), bufferSize, NULL, NULL);
        return buffer;
    }

    // Handle error (return NULL or throw an exception)
    return NULL;
}

vector<UCHAR> wstringToUcharArray(const wstring& str) {
    return vector<UCHAR>(str.begin(), str.end());
}

static map< wstring, vector<string>>  getVisibleNetworks(HANDLE hClient, GUID* pGuid) {

    map < wstring, vector<string>> networks;

    PWLAN_BSS_LIST bssList = NULL;
    PWLAN_BSS_ENTRY bssInfo = NULL;
    PDOT11_SSID ssid = NULL;
    PDOT11_MAC_ADDRESS bssid = NULL;

    DWORD dwResult = WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any, NULL, NULL, &bssList);
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"ERROR: WlanGetNetworkBssList failed with error: %u\n", dwResult);
    }
    else {
        for (int j = 0; j < (int)bssList->dwNumberOfItems; j++) {
            bssInfo = (WLAN_BSS_ENTRY*)&bssList->wlanBssEntries[j];
            ssid = (DOT11_SSID*)&bssInfo->dot11Ssid;
            bssid = (DOT11_MAC_ADDRESS*)&bssInfo->dot11Bssid;
            wstring ssidString = ConvertUcharToWstring(ssid->ucSSID);
            string bssidString = ConvertDot11MacAddressToString(*bssid);
            std::transform(bssidString.begin(), bssidString.end(), bssidString.begin(), [](wchar_t wc) { return std::towupper(wc); });
            networks[ssidString].push_back(bssidString);
        }
    }

    if (bssList != NULL){
        WlanFreeMemory(bssList);
        bssList = NULL;
    }
    return networks;
}

NET_LUID convertInterfaceAliasToLuid(wstring alias) {
    //cout << "interface alias to luid" << endl;
    const WCHAR* wcharAlias = alias.c_str();
    NET_LUID luid;
    DWORD dwResult;
    dwResult = ConvertInterfaceAliasToLuid(wcharAlias, &luid);
    if (dwResult != NO_ERROR) {
        wprintf(L"ERROR: ConvertInterfaceAliasToLuid failed with error: %u\n", dwResult);
    }
    return luid;
}

GUID convertLuidToGuid(PNET_LUID luid) {
    GUID guid;
    DWORD dwResult;
    dwResult = ConvertInterfaceLuidToGuid(luid, &guid);
    if (dwResult != NO_ERROR) {
        wprintf(L"ERROR: ConvertInterfaceLuidToGuid failed with error: %u\n", dwResult);
    }
    return guid;
}

GUID convertInterfaceAliasToGuid(wstring alias) {
    NET_LUID luid = convertInterfaceAliasToLuid(alias);
    return convertLuidToGuid(&luid);
}

void disconnect(HANDLE hClient, GUID* pGuid) {
    DWORD dwResult;
    dwResult = WlanDisconnect(hClient, pGuid, NULL);
    if (dwResult != NO_ERROR) {
        wprintf(L"ERROR: WlanDisconnect failed with error: %u\n", dwResult);
    }
    else {
        wprintf(L"SUCCESS: Disconnected successfully.");
    }
}

// Function to set values for DOT11_SSID
void setDot11SsidValues(PDOT11_SSID pSsidStructure, const wstring& ssid) {
    vector<UCHAR> ssidUcharArray = wstringToUcharArray(ssid);

    pSsidStructure->uSSIDLength = static_cast<ULONG>(ssidUcharArray.size());

    // Copy data to ucSSID array
    memcpy(pSsidStructure->ucSSID, ssidUcharArray.data(), ssidUcharArray.size());
}

void createBssidList(PDOT11_BSSID_LIST pBssidList, const vector<string>& bssids) {
    size_t numBssids = bssids.size();
    size_t structSize = sizeof(DOT11_BSSID_LIST) + (numBssids - 1) * sizeof(DOT11_MAC_ADDRESS);

    if (pBssidList != nullptr) {
        // Initialize NDIS_OBJECT_HEADER
        memset(&pBssidList->Header, 0, sizeof(NDIS_OBJECT_HEADER));
        pBssidList->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        pBssidList->Header.Revision = DOT11_BSSID_LIST_REVISION_1;
        pBssidList->Header.Size = (USHORT)structSize;

        // Set other members
        pBssidList->uNumOfEntries = static_cast<ULONG>(numBssids);
        pBssidList->uTotalNumOfEntries = static_cast<ULONG>(numBssids);

        // Allocate memory for BSSIDs
        pBssidList->BSSIDs[0];  // This is just a placeholder; it won't be used
        for (size_t i = 0; i < numBssids; ++i) {
            for (size_t j = 0; j < 6; ++j) {
                sscanf_s(bssids[i].c_str() + j * 3, "%2hhx", &pBssidList->BSSIDs[i][j]);
            }
        }

      
    }
}


map<string, string> getCurrentConnectionInfo(HANDLE hClient, GUID* pGuid) {
    map<string, string> connInfo;

    PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
    DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;
    DWORD dwResult = WlanQueryInterface(hClient, pGuid, wlan_intf_opcode_current_connection, NULL, &connectInfoSize, (PVOID*)&pConnectInfo, &opCode);

    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanQueryInterface failed with error: %u\n", dwResult);
    }
    else {
        string state;
        switch (pConnectInfo->isState) {
        case wlan_interface_state_not_ready:
            state = "Not ready";
            break;
        case wlan_interface_state_connected:
            state = "Connected";
            break;
        case wlan_interface_state_ad_hoc_network_formed:
            state = "First node in a ad hoc network";
            break;
        case wlan_interface_state_disconnecting:
            state = "Disconnecting";
            break;
        case wlan_interface_state_disconnected:
            state = "Not Connected";
            break;
        case wlan_interface_state_associating:
            state = "Attempting to associate with a network";
            break;
        case wlan_interface_state_discovering:
            state = "Auto configuration is discovering settings for the network";
            break;
        case wlan_interface_state_authenticating:
            state = "In process of authenticating";
            break;
        default:
            state = "Unknown state " + to_string(pConnectInfo->isState);
            break;
        }

        connInfo["state"] = state;

        string connectionMode = "";
        switch (pConnectInfo->wlanConnectionMode) {
        case wlan_connection_mode_profile:
            connectionMode = "A profile is used to make the connection";
            break;
        case wlan_connection_mode_temporary_profile:
            connectionMode = "A temporary profile is used to make the connection";
            break;
        case wlan_connection_mode_discovery_secure:
            connectionMode = "Secure discovery is used to make the connection";
            break;
        case wlan_connection_mode_discovery_unsecure:
            connectionMode = "Unsecure discovery is used to make the connection";
            break;
        case wlan_connection_mode_auto:
            connectionMode = "Connection initiated by wireless service automatically using a persistent profile";
            break;
        case wlan_connection_mode_invalid:
            connectionMode = "Invalid connection mode";
            break;
        default:
            connectionMode = "Unknown connection mode " + to_string(pConnectInfo->wlanConnectionMode);
            break;
        }
        connInfo["connectionMode"] = connectionMode;

        wstring_convert<codecvt_utf8<wchar_t>> converter;
        connInfo["profile"] = converter.to_bytes(pConnectInfo->strProfileName);

        string ssid = "";
        if (pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength > 0)
        {
            for (int k = 0; k < pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength; k++) {
                ssid += (int)pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID[k];
            }
        }
        connInfo["ssid"] = ssid;

        string bssNetworkType = "";
        switch (pConnectInfo->wlanAssociationAttributes.dot11BssType) {
        case dot11_BSS_type_infrastructure:
            bssNetworkType = "Infrastructure";
            break;
        case dot11_BSS_type_independent:
            bssNetworkType = "Independent";
            break;
        default:
            bssNetworkType = "Other " + to_string(pConnectInfo->wlanAssociationAttributes.dot11BssType);
            break;
        }
        connInfo["bssNetworkType"] = bssNetworkType;

        string bssid = ConvertDot11MacAddressToString(pConnectInfo->wlanAssociationAttributes.dot11Bssid);
        std::transform(bssid.begin(), bssid.end(), bssid.begin(), [](unsigned char c) { return std::toupper(c); });
        connInfo["bssid"] = bssid;

        string phyNetworkType = "";
        switch (pConnectInfo->wlanAssociationAttributes.dot11PhyType) {
        case dot11_phy_type_fhss:
            phyNetworkType = "Frequency-hopping spread-spectrum (FHSS)";
            break;
        case dot11_phy_type_dsss:
            phyNetworkType = "Direct sequence spread spectrum (DSSS)";
            break;
        case dot11_phy_type_irbaseband:
            phyNetworkType = "Infrared (IR) baseband";
            break;
        case dot11_phy_type_ofdm:
            phyNetworkType = "Orthogonal frequency division multiplexing (OFDM)";
            break;
        case dot11_phy_type_hrdsss:
            phyNetworkType = "High-rate DSSS (HRDSSS)";
            break;
        case dot11_phy_type_erp:
            phyNetworkType = "Extended rate PHY type";
            break;
        case dot11_phy_type_ht:
            phyNetworkType = "802.11n PHY type";
            break;
        case dot11_phy_type_vht:
            phyNetworkType = "802.11ac PHY type";
            break;
        case dot11_phy_type_dmg:
            phyNetworkType = "802.11ad PHY type";
            break;
        case dot11_phy_type_he:
            phyNetworkType = "802.11ax PHY type";
            break;
        case dot11_phy_type_eht:
            phyNetworkType = "802.11be PHY type";
            break;
        case dot11_phy_type_IHV_start:
            phyNetworkType = "IHV Start PHY type";
            break;
        case dot11_phy_type_IHV_end:
            phyNetworkType = "IHV End PHY type";
            break;
        default:
            phyNetworkType = "Unknown " + to_string(pConnectInfo->wlanAssociationAttributes.dot11PhyType);
            break;
        }
        connInfo["phyNetworkType"] = phyNetworkType;

        connInfo["phyIndex"] = to_string(pConnectInfo->wlanAssociationAttributes.uDot11PhyIndex);

        connInfo["signalQuality"] = to_string(pConnectInfo->wlanAssociationAttributes.wlanSignalQuality);

        connInfo["rxRate"] = to_string(pConnectInfo->wlanAssociationAttributes.ulRxRate);

        connInfo["txRate"] = to_string(pConnectInfo->wlanAssociationAttributes.ulTxRate);

        if (pConnectInfo->wlanSecurityAttributes.bSecurityEnabled == 0) {
            connInfo["securityEnable"] = "No";
        }
        else {
            connInfo["securityEnable"] = "Yes";
        }

        if (pConnectInfo->wlanSecurityAttributes.bOneXEnabled == 0) {
            connInfo["8021xEnabled"] = "No";
        }
        else {
            connInfo["8021xEnabled"] = "Yes";
        }

        string authAlgo = "";
        switch (pConnectInfo->wlanSecurityAttributes.dot11AuthAlgorithm) {
        case DOT11_AUTH_ALGO_80211_OPEN:
            authAlgo = "802.11 Open";
            break;
        case DOT11_AUTH_ALGO_80211_SHARED_KEY:
            authAlgo = "802.11 Shared";
            break;
        case DOT11_AUTH_ALGO_WPA:
            authAlgo = "WPA";
            break;
        case DOT11_AUTH_ALGO_WPA_PSK:
            authAlgo = "WPA-PSK";
            break;
        case DOT11_AUTH_ALGO_WPA_NONE:
            authAlgo = "WPA-None";
            break;
        case DOT11_AUTH_ALGO_RSNA:
            authAlgo = "RSNA";
            break;
        case DOT11_AUTH_ALGO_RSNA_PSK:
            authAlgo = "RSNA with PSK";
            break;
        case DOT11_AUTH_ALGO_WPA3_ENT_192:
            authAlgo = "WPA3-Enterprise-192bit or WPA3";
            break;
        case DOT11_AUTH_ALGO_WPA3_SAE:
            authAlgo = "WPA3-SAE";
            break;
        case DOT11_AUTH_ALGO_OWE:
            authAlgo = "OWE";
            break;
        case DOT11_AUTH_ALGO_WPA3_ENT:
            authAlgo = "WPA3-Enterprise";
            break;
        case 0x80000000:
            authAlgo = "DOT11_AUTH_ALGO_IHV_START";
            break;
        case 0xffffffff:
            authAlgo = "DOT11_AUTH_ALGO_IHV_END";
            break;
        default:
            authAlgo = "Other " + to_string(pConnectInfo->wlanSecurityAttributes.dot11AuthAlgorithm);
            break;
        }

        connInfo["authenticationAlgorithm"] = authAlgo;

        string cipher = "";
        switch (pConnectInfo->wlanSecurityAttributes.dot11CipherAlgorithm) {
        case DOT11_CIPHER_ALGO_NONE:
            cipher = "None";
            break;
        case DOT11_CIPHER_ALGO_WEP40:
            cipher = "WEP-40";
            break;
        case DOT11_CIPHER_ALGO_TKIP:
            cipher = "TKIP";
            break;
        case DOT11_CIPHER_ALGO_CCMP:
            cipher = "CCMP";
            break;
        case DOT11_CIPHER_ALGO_WEP104:
            cipher = "WEP-104";
            break;
        case DOT11_CIPHER_ALGO_WEP:
            cipher = "WEP";
            break;
        case DOT11_CIPHER_ALGO_BIP:
            cipher = "BIP";
            break;
        case DOT11_CIPHER_ALGO_GCMP:
            cipher = "GCMP";
            break;
        case DOT11_CIPHER_ALGO_GCMP_256:
            cipher = "GCMP-256";
            break;
        case DOT11_CIPHER_ALGO_CCMP_256:
            cipher = "CCMP-256";
            break;
        case DOT11_CIPHER_ALGO_BIP_GMAC_128:
            cipher = "BIP-GMAC-128";
            break;
        case DOT11_CIPHER_ALGO_BIP_GMAC_256:
            cipher = "BIP-GMAC-256";
            break;
        case DOT11_CIPHER_ALGO_BIP_CMAC_256:
            cipher = "BIP-CMAC-256";
            break;
        case DOT11_CIPHER_ALGO_WPA_USE_GROUP:
            cipher = "WPA-USE-GROUP or RSN-USE-GROUP";
            break;
        case DOT11_CIPHER_ALGO_IHV_START:
            cipher = "IHV-START";
            break;
        case DOT11_CIPHER_ALGO_IHV_END:
            cipher = "IHV-END";
            break;
        default:
            cipher = "Other " + to_string(pConnectInfo->wlanSecurityAttributes.dot11CipherAlgorithm);
            break;
        }
        connInfo["cipherAlgorithm"] = cipher;
    }

    return connInfo;
}

void getConnectionParams(PWLAN_CONNECTION_PARAMETERS connParams, PDOT11_SSID pSsid,PDOT11_BSSID_LIST pBssidList,wstring profile, wstring ssid, vector<string> bssids) {
    // Set values for ssidStructure
    setDot11SsidValues(pSsid, ssid);
 
    connParams->wlanConnectionMode = wlan_connection_mode_profile;

    connParams->strProfile = profile.c_str();
    connParams->pDot11Ssid = pSsid;
    createBssidList(pBssidList, bssids);
    connParams->pDesiredBssidList = pBssidList;
    connParams->dwFlags = 0x00000000;
    connParams->dot11BssType = dot11_BSS_type_any;
}

void connect(HANDLE hClient, GUID* pGuid, wstring ssid, vector<string> bssids, int attempts) {
    DWORD dwResult;
    int initNumBssids = bssids.size();
    if (bssids.size() == 0){
        bssids = getVisibleNetworks(hClient, pGuid)[ssid];
    }

    PWLAN_CONNECTION_PARAMETERS connParams = (PWLAN_CONNECTION_PARAMETERS)malloc(sizeof(WLAN_CONNECTION_PARAMETERS));;
    size_t numBssids = bssids.size();
    size_t structSize = sizeof(DOT11_BSSID_LIST) + (numBssids - 1) * sizeof(DOT11_MAC_ADDRESS);
    PDOT11_BSSID_LIST bssidList = (PDOT11_BSSID_LIST)malloc(structSize);
    PDOT11_SSID pSsid = (PDOT11_SSID)malloc(sizeof(DOT11_SSID));
    getConnectionParams(connParams, pSsid, bssidList, ssid, ssid, bssids);

    map<string, string> connInfo;
    for (int attempt = 0; attempt < attempts; attempt++) {
        dwResult = WlanConnect(hClient, pGuid, connParams, NULL);
        if (dwResult != NO_ERROR) {
            wprintf(L"ERROR: WlanConnect failed with error: %u\n", dwResult);
        }

        // Some authentications like EAP-TLS take time. So sleep for 5 seconds.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        try {
            connInfo = getCurrentConnectionInfo(hClient, pGuid);
            wstring_convert<codecvt_utf8<wchar_t>> converter;
            string inputSsid = converter.to_bytes(ssid);
            string currSsid = connInfo["ssid"];
            string currBssid = connInfo["bssid"];
            if (currSsid == inputSsid && initNumBssids ==0) {
                wprintf(L"SUCCESS: Connected successfully.");
                return;
            }
            else if (currSsid == inputSsid && initNumBssids > 0) {
                auto it = find(bssids.begin(), bssids.end(),currBssid);
                if (it != bssids.end()) {
                    wprintf(L"SUCCESS: Connected successfully.");
                    return;
                }
                else {
                    cout << "Connected to BSSID " << currBssid << " of SSID " << currSsid << endl;
                    cout << "Retrying connection to the specified BSSID of SSID " << inputSsid << " - attempt " << attempt+1 << endl;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Exception caught: " << e.what() << std::endl;
        }

    }
    

    // Free allocated memory
    free(connParams);
    free(pSsid);
    free(bssidList);
}

long getRssi(HANDLE hClient, GUID* pGuid) {
    PDWORD rssiSizePointer = (PDWORD)malloc(sizeof(DWORD));
    PVOID rssiPointer = (PVOID)malloc(sizeof(long));
    long rssi = 0;
    WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_query_only;

    DWORD dwResult = WlanQueryInterface(hClient, pGuid, wlan_intf_opcode_rssi, NULL, rssiSizePointer, &rssiPointer, &opCode);

    if (dwResult == ERROR_SUCCESS && *rssiSizePointer > 0) {
        rssi = *(long*)rssiPointer;
    }
    else {
        // Handle error during the first query
        wprintf(L"ERROR: WlanQueryInterface for RSSI failed with error: %u\n", dwResult);
    }

    // Don't forget to free the allocated memory when you are done with it
    free(rssiPointer);
    return rssi;
}

wstring getPeapXml(wstring username, wstring password) {
    wstring defaultXml = LR"(<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials"><EapMethod><eapCommon:Type>25</eapCommon:Type><eapCommon:AuthorId>0</eapCommon:AuthorId></EapMethod><Credentials xmlns:eapUser="http://www.microsoft.com/provisioning/EapUserPropertiesV1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1" xmlns:MsPeap="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1" xmlns:MsChapV2="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1"><baseEap:Eap><baseEap:Type>25</baseEap:Type><MsPeap:EapType><baseEap:Eap><baseEap:Type>26</baseEap:Type><MsChapV2:EapType><MsChapV2:Username>saran</MsChapV2:Username><MsChapV2:Password>welcome123</MsChapV2:Password></MsChapV2:EapType></baseEap:Eap></MsPeap:EapType></baseEap:Eap></Credentials></EapHostUserCredentials>)";

    // Replace default Username 
    size_t startPos = defaultXml.find(L"saran");
    size_t replaceCount = 5; // Length of "saran"
    
    if (startPos != wstring::npos) {
        defaultXml.replace(startPos, replaceCount, username);
    }
    else {
        std::cout << "ERROR: Username Substring not found." << std::endl;
    }

    // Replace default password 
    startPos = defaultXml.find(L"welcome123");
    replaceCount = 10; // Length of "welcome123"

    if (startPos != wstring::npos) {
        defaultXml.replace(startPos, replaceCount, password);
    }
    else {
        std::cout << "ERROR: Password Substring not found." << std::endl;
    }

    return defaultXml;
}

void setPeapCredentials(HANDLE hClient,GUID* pGuid, wstring ssid, wstring username, wstring password) {
    if (username == L"" || password == L"" || ssid == L"") {
        wprintf(L"ERROR: SSID, Username and Password should be provided for setting PEAP credentials.\n");
        return;
    }

    wstring userXml = getPeapXml(username, password);
    DWORD dwResult = WlanSetProfileEapXmlUserData(hClient, pGuid, ssid.c_str(), 1, userXml.c_str(), NULL);
    
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"ERROR: WlanSetProfileEapXmlUserData failed with error: %u\n", dwResult);
    }
    else {
        wprintf(L"SUCCESS: PEAP-MSCHAPv2 User credentials are set successfully.");
    }
}

void helpDescription() {
    printf("\nWLAN Explorer v0.3\n\n");
    printf("SYNTAX: wlanExplorer.exe -interface [INTERFACE_NAME] -action [ACTION] -ssid [SSID_NAME] -bssid [BSSID] -attempts [ATTEMPTS] -username [USERNAME] -password [PASSWORD]\n");
    printf("actions -> connect, disconnect, getAllBssids, getAllSsids, getAllBssidsOfSsid, getCurrentConnectionInfo, setPeapCredentials\n");
    printf("If BSSID is not provided, Windows OS will choose the BSSID.\n");
    printf("Default value for attempts is 1.\n");
}

int wmain(int argc,  wchar_t* argv[])
{
    // Parse and sanitize input arguments
    wstring interfaceAlias=L"";
    wstring action=L"";
    wstring ssid=L"";
    wstring bssid=L"";
    wstring username = L"";
    wstring password = L"";
    int attempts = 1;

    if (argc == 1) {
        wprintf(L"0 arguments provided\n");
        helpDescription();
        return 1;
    }
    else {
        // Variables used for input argument parsing
        wstring key;
        wstring interfaceKey = L"-interface";
        wstring actionKey    = L"-action";
        wstring ssidKey      = L"-ssid";
        wstring bssidKey     = L"-bssid";
        wstring attemptKey   = L"-attempts";
        wstring userNameKey  = L"-username";
        wstring passwordKey  = L"-password";
        wstring helpKey      = L"-help";

        for (int i = 1; i < argc; i+=2) {
            key = argv[i];
            if (key == interfaceKey && i + 1 < argc) {
                interfaceAlias = argv[i + 1];
            }
            else if(key == actionKey && i + 1 < argc) {
                action = argv[i + 1];
            }
            else if(key == ssidKey && i + 1 < argc) {
                ssid = argv[i + 1];
            }
            else if (key == userNameKey && i + 1 < argc) {
                username = argv[i + 1];
            }
            else if (key == passwordKey && i + 1 < argc) {
                password = argv[i + 1];
            }
            else if(key == bssidKey && i + 1 < argc) {
                bssid = argv[i + 1];
                // Convert BSSID to upper case
                std::transform(bssid.begin(), bssid.end(), bssid.begin(),[](wchar_t wc) { return std::towupper(wc); });
                wcout << bssid << endl;
            }
            else if (key == attemptKey && i + 1 < argc) {
                attempts = stoi(argv[i + 1]);
                if (attempts < 1) {
                    wcout << "ERROR: Incorrect attempts : " << key;
                    cout << attempts << endl;
                    cout << "Exiting." << endl;
                    return 1;
                }
            }
            else if (key == helpKey) {
                helpDescription();
                return 0;
            }
            else {
                wcout << "ERROR: Unknown key : " << key << endl;
                cout << "Exiting." << endl;
                return 1;
            }
        }
    }

    // Get GUID from interface Alias
    GUID guid = convertInterfaceAliasToGuid(interfaceAlias);

    // Variables used for WlanOpenHandle
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;        
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    DWORD dwRetVal = 0;

    // Open WLAN handle
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"ERROR: WlanOpenHandle failed with error: %u\n", dwResult);
        return 1;
    }

    // Get Visible networks
    map <wstring, vector<string>> networks = getVisibleNetworks(hClient, &guid);

    // Print according to action
    if (action == L"getAllSsids") {
        // Print all SSIDs and their corresponding BSSIDs
        for (auto it = networks.begin(); it != networks.end(); it++) {
            wcout << L"SSID: " << it->first << endl;
            for (string item : it->second) {
                string temp = item;
                std::transform(temp.begin(), temp.end(), temp.begin(), [](char wc) { return std::toupper(wc); });
                std::cout << "    BSSID: " << temp << std::endl;
            }
        }
    }
    else if (action == L"getAllBssids") {
        // Print all BSSIDs
        for (auto it = networks.begin(); it != networks.end(); it++) {
            for (string item : it->second) {
                string temp = item;
                std::transform(temp.begin(), temp.end(), temp.begin(), [](char wc) { return std::toupper(wc); });
                std::cout<< temp << std::endl;
            }
        }
    }
    else if (action == L"getAllBssidsOfSsid") {
        // Print all BSSIDs of an SSID
        for (auto it = networks.begin(); it != networks.end(); it++) {
            if (it->first == ssid) {
                for (string item : it->second) {
                    string temp = item;
                    std::transform(temp.begin(), temp.end(), temp.begin(), [](char wc) { return std::toupper(wc); });
                    std::cout << temp << std::endl;
                }
            }
        }
    }
    else if (action == L"disconnect") {
        // Disconnect the Wireless interface from an SSID
        disconnect(hClient, &guid);
    }
    else if (action == L"connect") {
        bool ssidFound = false;

        // Find the SSID from visible SSIDs map
        for (auto it = networks.begin(); it != networks.end(); it++) {
            if (it->first == ssid) {
                ssidFound = true;

                // Connect with all BSSIDs as preferred BSSID is BSSID is not provided
                if (bssid == L"") {
                    connect(hClient, &guid, ssid, it->second, attempts);
                }
                else {
                    // Convert BSSID from wstring to string
                    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
                    std::string strBssid = converter.to_bytes(bssid);

                    // Initialize preferred BSSID vector
                    bool bssidFound = false;
                    vector<string>preferredBssid = { strBssid };
                    for (string visibleBssid : it->second) {
                        if (visibleBssid == strBssid) {
                            bssidFound = true;
                            connect(hClient, &guid, ssid, preferredBssid, attempts);
                        }
                    }
                    // Logs for a case where BSSID is not found.
                    if (!bssidFound) {
                        cout << "ERROR: BSSID " << strBssid << " is not visible for SSID ";
                        wcout << ssid;
                        cout << ". Visible BSSIDs are ";
                        for (string visibleBssid : it->second) {
                            cout << visibleBssid << " ";
                        }
                        cout << endl;
                    }
                }
            }
        }
        if (!ssidFound) {
            wcout << "ERROR: SSID " << ssid << " is not visible" << endl;
        }
    }
    else if (action == L"getCurrentConnectionInfo") {
        map<string, string> connInfo = getCurrentConnectionInfo(hClient, &guid);
        for (auto it = connInfo.begin(); it != connInfo.end(); it++) {
            cout << it->first << " : " << it->second << endl;
        }

    }
    else if (action == L"setPeapCredentials") {
        setPeapCredentials(hClient, &guid, ssid, username, password);
    }

    // Close WLAN handle
    dwResult = WlanCloseHandle(hClient, NULL);
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanCloseHandle failed with error: %u\n", dwResult);
        return 1;
    }

    return 0;
}