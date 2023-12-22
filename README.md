# WLAN-Explorer
A tool to interact with native Wifi APIs on Windows clients

## Help

PS C:\saran> .\wlanExplorer.exe -help

WLAN Explorer v0.2

SYNTAX: wlanExplorer.exe -interface [INTERFACE_NAME] -action [ACTION] -ssid [SSID_NAME] -bssid [BSSID] -attempts [ATTEMPTS]

actions -> connect, disconnect, getAllBssids, getAllSsids, getAllBssidsOfSsid, getCurrentConnectionInfo

If BSSID is not provided, Windows OS will choose the BSSID.

Default value for attempts is 1.

## Version 0.2 Highlights

1. We can provide an interface name instead of the interface GUID making this more user-friendly
2. BSSID is optional while connecting the client. If BSSID is not provided, Windows OS will pick the best BSSID
3. This is now written in C++ instead of Python. This makes the code faster and binary lighter (7.9 MB to 429KB)
