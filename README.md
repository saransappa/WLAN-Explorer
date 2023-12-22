# WLAN-Explorer
A tool to interact with native Wifi APIs on Windows clients

# Help

PS C:\saran> .\wlanExplorer.exe -help

WLAN Explorer v0.2

SYNTAX: wlanExplorer.exe -interface [INTERFACE_NAME] -action [ACTION] -ssid [SSID_NAME] -bssid [BSSID] -attempts [ATTEMPTS]

actions -> connect, disconnect, getAllBssids, getAllSsids, getAllBssidsOfSsid, getCurrentConnectionInfo

If BSSID is not provided, Windows OS will choose the BSSID.

Default value for attempts is 1.
