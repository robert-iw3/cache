#!/bin/bash

# ======================================================================================
# Script Name: threat_intel_check.sh
# Description: Automates external Threat Intelligence (CTI) enrichment for suspicious
#              IP addresses identified by the ML detection pipeline.
# Operations Performed:
#   1. Parses config.ini to retrieve API keys securely.
#   2. Reads the anomalies JSONL log to extract all unique, non-local destination
#      IPs associated with a high anomaly score (>= 80).
#   3. Queries multiple external APIs (VirusTotal, AlienVault OTX, GreyNoise,
#      AbuseIPDB, and Shodan) to gather reputation, campaign association, and
#      infrastructure profiling data.
#   4. Outputs a consolidated, human-readable text report containing the findings.
# Note:        Includes deliberate sleep intervals to avoid rate-limiting on
#              free-tier community API accounts.
#
# Operations:
#   - Filters OTX pulses for modern frameworks (Sliver, Havoc, Nighthawk, Covenant, etc.).
#   - Extracts JARM TLS fingerprints to identify unmasked teamserver signatures.
#   - Identifies Behavior/Categories and Masking (VPN/Tor) for high-fidelity triage.
# ======================================================================================

CONFIG_FILE="config.ini"

get_config() {
    grep "^$1=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' 2>/dev/null
}

LOG_FILE=$(get_config "LOG_FILE")
LOG_FILE=${LOG_FILE:-"../output/anomalies.jsonl"}
OUTPUT_DIR=$(get_config "OUTPUT_DIR")
OUTPUT_DIR=${OUTPUT_DIR:-"../output/"}
REPORT_OUT="${OUTPUT_DIR}threat_intel_report_$(date +%Y%m%d_%H%M%S).txt"

# Load API Keys
VT_API_KEY=$(get_config "VIRUSTOTAL_KEY")
OTX_API_KEY=$(get_config "ALIENVAULT_OTX_KEY")
GN_API_KEY=$(get_config "GREYNOISE_KEY")
ABUSEIPDB_KEY=$(get_config "ABUSEIPDB_KEY")
SHODAN_KEY=$(get_config "SHODAN_KEY")

if [ ! -f "$LOG_FILE" ]; then
    echo "[!] Error: Cannot find log file at $LOG_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
SUSPICIOUS_IPS=$(jq -r 'select(.score >= 80 and .dst_ip != "0.0.0.0") | .dst_ip' "$LOG_FILE" | sort -u)

if [ -z "$SUSPICIOUS_IPS" ]; then
    echo "[+] No remote external IPs found to investigate."
    exit 0
fi

echo "============================================================" | tee "$REPORT_OUT"
echo "[*] ENHANCED BEHAVIORAL CTI ENRICHMENT" | tee -a "$REPORT_OUT"
echo "============================================================" | tee -a "$REPORT_OUT"

for IP in $SUSPICIOUS_IPS; do
    echo "------------------------------------------------------------" | tee -a "$REPORT_OUT"
    echo "TARGET IP: $IP" | tee -a "$REPORT_OUT"
    echo "------------------------------------------------------------" | tee -a "$REPORT_OUT"

    # 1. VirusTotal: Categorization with Null Handling
    if [ -n "$VT_API_KEY" ]; then
        echo "    -> Querying VirusTotal..."
        VT_RES=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/ip_addresses/$IP" --header "x-apikey: $VT_API_KEY")
        VT_MAL=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious // "0"')
        # Uses ? to prevent 'null has no keys' errors and handles missing categories
        VT_CATS=$(echo "$VT_RES" | jq -r '.data.attributes.categories? | if . then to_entries | map(.value) | join(", ") else "None" end')
        echo "       - VT Malicious Hits: $VT_MAL" | tee -a "$REPORT_OUT"
        echo "       - Behavior/Categories: $VT_CATS" | tee -a "$REPORT_OUT"
    fi

    # 2. AlienVault OTX: Focused Framework Identification
    if [ -n "$OTX_API_KEY" ]; then
        echo "    -> Querying AlienVault OTX..."
        OTX_RES=$(curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" -H "X-OTX-API-KEY: $OTX_API_KEY")
        FRAMEWORK_REGEX="Sliver|Mythic|Havoc|Empire|Cobalt|Metasploit|Brute|Deery|Nighthawk|Covenant|Manjusaka|PoshC2|Merlin|SharpC2|Koadic|Viper|S3cret|Godzilla|Behinder|Chisel|Ligolo|Insecure|Venom|Xray"
        # Uses ? to handle missing pulses and filters for specific frameworks
        OTX_TAGS=$(echo "$OTX_RES" | jq -r --arg re "$FRAMEWORK_REGEX" '.pulse_info.pulses? | if . then map(.tags[]?) | unique | map(select(test($re; "i"))) | join(", ") else "" end')

        if [ -z "$OTX_TAGS" ]; then
            OTX_COUNT=$(echo "$OTX_RES" | jq -r '.pulse_info.count // "0"')
            OTX_TAGS="No specific framework match (Associated Pulses: $OTX_COUNT)"
        fi
        echo "       - C2 Framework Match: $OTX_TAGS" | tee -a "$REPORT_OUT"
    fi

    # 3. AbuseIPDB: Confidence Score
    if [ -n "$ABUSEIPDB_KEY" ]; then
        echo "    -> Querying AbuseIPDB..."
        ABIP_RES=$(curl -s -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$IP" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json")
        ABIP_SCORE=$(echo "$ABIP_RES" | jq -r '.data.abuseConfidenceScore // "0"')
        echo "       - Abuse Confidence Score: $ABIP_SCORE%" | tee -a "$REPORT_OUT"
    fi

    # 4. GreyNoise: Masking & Noise Context
    if [ -n "$GN_API_KEY" ]; then
        echo "    -> Querying GreyNoise..."
        GN_RES=$(curl -s "https://api.greynoise.io/v3/community/$IP" -H "key: $GN_API_KEY")
        GN_VPN=$(echo "$GN_RES" | jq -r '.vpn // "false"')
        GN_TOR=$(echo "$GN_RES" | jq -r '.tor // "false"')
        GN_CLASS=$(echo "$GN_RES" | jq -r '.classification // "Unknown"')
        echo "       - GreyNoise Class: $GN_CLASS" | tee -a "$REPORT_OUT"
        echo "       - Proxy Masking: VPN:$GN_VPN | TOR:$GN_TOR" | tee -a "$REPORT_OUT"
    fi

    # 5. Shodan: Fixed JARM and Product Extraction
    if [ -n "$SHODAN_KEY" ]; then
        echo "    -> Querying Shodan..."
        SH_RES=$(curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY")
        # JARM TLS Fingerprint extraction with null protection
        JARM=$(echo "$SH_RES" | jq -r '.tags? | if . then map(select(contains("jarm")))? | join(", ") else "None" end')
        # Replaced 'compact' with 'select(. != null)' for standard jq compatibility
        PROD=$(echo "$SH_RES" | jq -r '.data? | if . then map(.product) | unique | map(select(. != null)) | join(", ") else "None" end')
        echo "       - JARM TLS Fingerprint: $JARM" | tee -a "$REPORT_OUT"
        echo "       - Fingerprinted Products: $PROD" | tee -a "$REPORT_OUT"
    fi

    echo "" | tee -a "$REPORT_OUT"
    sleep 2
done

echo "============================================================" | tee -a "$REPORT_OUT"
echo "[*] Enrichment Complete. See $REPORT_OUT" | tee -a "$REPORT_OUT"
echo "============================================================" | tee -a "$REPORT_OUT"