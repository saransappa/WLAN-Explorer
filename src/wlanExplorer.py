import argparse
import sys
import time
from Win32Wifi import *

def getInterfaceFromGuid(guid):
    interfaces = getWirelessInterfaces()
    for interface in interfaces:
        if interface.guid_string == guid:
            return interface

def getCurrentConnectionInfo(intf):
    return queryInterface(intf, "current_connection")[1]

def getAllVisibleBssids(intf):
    bssidObjects = getWirelessNetworkBssList(intf)
    bssids = [str(bssidObject.bssid) for bssidObject in bssidObjects]
    return bssids

def getAllVisibleNetworks(intf):
    bssidObjects = getWirelessNetworkBssList(intf)
    networks     = [(str(bssidObject.bssid),str(bssidObject.ssid)[2:-1]) for bssidObject in bssidObjects]
    return networks

def getAllVisibleBssidsOfSsid(intf, ssid):
    networks = getAllVisibleNetworks(intf=intf)
    bssids   = [network[0] for network in networks if network[1] == ssid]
    return bssids

def connectToBssid(intf, ssid, bssid, attempts):
    bssid = bssid.upper()
    for attempt in range(attempts):
        if attempt > 0:
            print(f'Connection Retry - {attempt}')
        visibleBssids = getAllVisibleBssidsOfSsid(intf=intf, ssid=ssid)
        if not visibleBssids:
            print(f'ERROR: {ssid} is not visible')
            if attempt == attempts-1:
                sys.exit(1)
            else:
                continue
        
        if bssid not in visibleBssids:
            print(f'ERROR: {bssid} of {ssid} is not visible. Visible BSSIDs -> {visibleBssids}')
            if attempt == attempts-1:
                sys.exit(2)
            else:
                continue

        connect(intf, connection_params={'connectionMode': 'wlan_connection_mode_profile',
                                            'profile': ssid,
                                            'ssid': bytes(ssid, encoding='utf-8'),
                                            'bssidList': [bytes(bssid, encoding='utf-8')],
                                            'bssType': 'dot11_BSS_type_infrastructure',
                                            'flags': 0x00000000})

        # Wait for currentConnectionInfo to get populated. EAP-TLS exchange takes time.
        time.sleep(10)
        try:
            currentConnectionInfo = getCurrentConnectionInfo(intf=intf)
            if currentConnectionInfo['strProfileName'] != ssid:
                print(f'ERROR: Could not connect to {ssid}. Currently connected to {currentConnectionInfo['strProfileName']}')
                if attempt == attempts-1:
                    sys.exit(3)
                else:
                    continue

            if currentConnectionInfo['wlanAssociationAttributes']['dot11Bssid'] != bssid:
                print(f'ERROR: Could not connect to {bssid}. Currently connected to {currentConnectionInfo['wlanAssociationAttributes']['dot11Bssid']}')
                if attempt == attempts-1:
                    sys.exit(4)
                else:
                    continue
            
            print(f'SUCCESS: Connected to BSSID {bssid} of SSID {ssid}')
            return
        except Exception as errMsg:
            if errMsg == 'WlanQueryInterface failed.':
                print('ERROR: Connection failed')

def disconnectInterface(intf, attempts):
    for attempt in range(attempts):
        if attempt > 0:
            print(f'Disconnection Retry - {attempt}')
        disconnect(intf)
        try:
            currentConnectionInfo = getCurrentConnectionInfo(intf=intf)
            if currentConnectionInfo['strProfileName']:
                print(f'ERROR: Unable to disconnect. Connected to {currentConnectionInfo['strProfileName']}')
                sys.exit(5)
        except:
            print('SUCCESS: Disconnected')
            return


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-guid', default=-1,help='GUID of the Wireless Interface')
    parser.add_argument('-action', default=-1, help='Wireless action to be performed (connect, disconnect, getAllBssidsOfSsid, getAllVisibleBssids, getAllVisibleNetworks, getCurrentConnectionInfo)')
    parser.add_argument('-ssid', default=-1, help='SSID name')
    parser.add_argument('-bssid', default=-1, help='BSSID of the SSID provided')
    parser.add_argument('-attempts', default=3, help='No.of attempts for connection/disconnection. Default - 3')
    options = parser.parse_args()

    # Get interface object from GUID
    if options.guid == -1:
        print(f'ERROR: An interface GUID must be speicied')
        sys.exit(6)
    
    try:
        intf = getInterfaceFromGuid(options.guid)
    except:
        print(f'ERROR: Incorrect GUID {options.guid} specified.')

    # Call function according to the action
    if options.action == -1:
        print(f'ERROR: An action must be specified. Choose one from (connect, disconnect, getAllBssidsOfSsid, getAllVisibleBssids, getAllVisibleNetworks, getCurrentConnectionInfo)')
        sys.exit(7)
    elif options.action == 'getCurrentConnectionInfo':
        print(getCurrentConnectionInfo(intf=intf))
    elif options.action == 'getAllVisibleBssids':
        bssids = getAllVisibleBssids(intf=intf)
        print('\n'.join(bssids))
    elif options.action == 'getAllVisibleNetworks':
        networks = getAllVisibleNetworks(intf=intf) 
        for network in networks:
            print(network[0], network[1])
    elif options.action == 'getAllBssidsOfSsid':
        bssids = getAllVisibleBssidsOfSsid(intf=intf, ssid=options.ssid)
        print('\n'.join(bssids))
    elif options.action == 'disconnect':
        disconnectInterface(intf=intf,attempts=int(options.attempts))
    elif options.action == 'connect':
        # Get wireless profiles
        profiles = getWirelessProfiles(intf)
        profileFound = False
        for profile in profiles:
            if profile.name == options.ssid:
                profileFound = True
                break
        
        # Exit if Wireless profile is not found
        if not profileFound:
            print(f'ERROR: {options.ssid} is not configured. Please add the profile first')
            sys.exit(8)
        
        if options.bssid == -1:
            print(f'ERROR: BSSID is not provided')
            sys.exit(9)

        connectToBssid(intf=intf, ssid=options.ssid, bssid=options.bssid, attempts=int(options.attempts))