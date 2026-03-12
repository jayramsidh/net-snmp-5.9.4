/*
 * ifWifiTable_data_access.c
 *
 * Data collection layer for WiFi MIB extension.
 * Reads from three Linux sources:
 *   1. /proc/net/wireless    — signal, noise, link quality
 *   2. `iw dev <if> link`    — SSID, BSSID, bitrate, MCS, channel
 *   3. `iw dev <if> station dump` — tx/rx counters, retries, failures
 *
 * This file maps directly to the pattern used in net-snmp V5-9-3:
 *   agent/mibgroup/if-mib/ifTable/ifTable_data_access.c
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <net/if.h>         /* IFNAMSIZ */

#include "ifWifiTable.h"

/* ── Internal linked list of discovered WiFi interfaces ─────────────────── */
static ifWifiData  *wifi_table   = NULL;
static int          wifi_count   = 0;
static time_t       wifi_loaded  = 0;

/* ============================================================================
 * INTERNAL HELPERS
 * ========================================================================== */

/* Trim leading/trailing whitespace in-place */
static char *strtrim(char *s)
{
    char *end;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return s;
}

/* Parse a line like "1c:bf:ce:aa:bb:cc" into a 6-byte array */
static int parse_mac(const char *str, unsigned char *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6;
}

/* Convert frequency in MHz to channel number */
static int freq_to_channel(int freq_mhz)
{
    if (freq_mhz == 2484) return 14;
    if (freq_mhz >= 2412 && freq_mhz <= 2472)
        return (freq_mhz - 2412) / 5 + 1;
    if (freq_mhz >= 5180 && freq_mhz <= 5825)
        return (freq_mhz - 5000) / 5;
    if (freq_mhz >= 5955 && freq_mhz <= 7115)   /* 6 GHz */
        return (freq_mhz - 5955) / 5 + 1;
    return 0;
}

/* Determine band from frequency */
static int freq_to_band(int freq_mhz)
{
    if (freq_mhz >= 2400 && freq_mhz < 2500) return IFWIFI_BAND_2GHZ;
    if (freq_mhz >= 5000 && freq_mhz < 5950) return IFWIFI_BAND_5GHZ;
    if (freq_mhz >= 5950 && freq_mhz < 7200) return IFWIFI_BAND_6GHZ;
    if (freq_mhz >= 57000)                    return IFWIFI_BAND_60GHZ;
    return IFWIFI_BAND_UNKNOWN;
}

/* ============================================================================
 * SOURCE 1: /proc/net/wireless
 *
 * Format (after 2 header lines):
 *   wlan0: 0000  55.  -56.  -95.    0    0    0    0    0    0
 *          ^name ^st  ^lq  ^sig  ^noise  ...
 *
 * Columns: iface status link_qual signal noise nwid crypt frag retry misc beacon
 * Values with trailing '.' are in dBm, without are arbitrary units.
 * ========================================================================== */
static int read_proc_wireless(ifWifiData *d)
{
    FILE   *fp;
    char    line[256];
    char    iface[IFNAMSIZ];
    int     status;
    float   lq, sig, noise;
    int     lq_max = 70;     /* typical driver maximum */
    int     lineno = 0;

    fp = fopen("/proc/net/wireless", "r");
    if (!fp) {
        DEBUGMSGTL(("ifWifi", "Cannot open /proc/net/wireless\n"));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (lineno <= 2) continue;   /* skip header lines */

        /* Parse: "  wlan0: 0000  55.  -56.  -95.  0  0  0  0  0  0" */
        if (sscanf(line, " %15[^:]: %x %f. %f. %f.",
                   iface, &status, &lq, &sig, &noise) >= 4) {

            if (strcmp(iface, d->ifName) == 0) {
                d->link_quality     = (unsigned int)lq;
                d->link_quality_max = lq_max;
                d->signal_dbm       = (int)sig;
                d->noise_dbm        = (int)noise;
                d->snr_db           = d->signal_dbm - d->noise_dbm;
                if (d->snr_db < 0) d->snr_db = 0;
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;   /* interface not found */
}

/* ============================================================================
 * SOURCE 2: `iw dev <iface> link`
 *
 * Example output when connected:
 *   Connected to aa:bb:cc:dd:ee:ff (on wlan0)
 *         SSID: MyNetwork
 *         freq: 5240
 *         RX: 12345678 bytes (98765 packets)
 *         TX: 9876543 bytes (54321 packets)
 *         signal: -65 dBm
 *         rx bitrate: 300.0 MBit/s MCS 15 40MHz short GI
 *         tx bitrate: 270.0 MBit/s MCS 13 40MHz short GI
 *
 * Example output when NOT connected:
 *   Not connected.
 * ========================================================================== */
static int read_iw_link(ifWifiData *d)
{
    FILE   *fp;
    char    cmd[128];
    char    line[512];
    int     freq = 0;

    snprintf(cmd, sizeof(cmd), "iw dev %s link 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return -1;

    d->connected = 2;   /* false by default (TruthValue) */
    memset(d->bssid, 0, 6);
    d->ssid[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);

        if (strncmp(s, "Connected to", 12) == 0) {
            char mac_str[18] = {0};
            if (sscanf(s, "Connected to %17s", mac_str) == 1) {
                parse_mac(mac_str, d->bssid);
                d->connected = 1;   /* true */
            }
        }
        else if (strncmp(s, "SSID:", 5) == 0) {
            strncpy(d->ssid, strtrim(s + 5), 32);
        }
        else if (strncmp(s, "freq:", 5) == 0) {
            sscanf(s + 5, "%d", &freq);
            d->channel       = freq_to_channel(freq);
            d->band          = freq_to_band(freq);
        }
        else if (strncmp(s, "signal:", 7) == 0) {
            sscanf(s + 7, "%d", &d->signal_dbm);
        }
        else if (strncmp(s, "tx bitrate:", 11) == 0) {
            float rate_mbps = 0;
            int   mcs = -1;
            char  mhz_str[16] = {0};

            sscanf(s + 11, "%f MBit/s MCS %d %15s", &rate_mbps, &mcs, mhz_str);
            d->tx_bitrate_100bps = (unsigned long)(rate_mbps * 10000);
            d->tx_mcs = mcs;

            /* Parse channel width from "40MHz" / "80MHz" / "160MHz" */
            if (strstr(mhz_str, "160")) d->channel_width_mhz = 160;
            else if (strstr(mhz_str, "80"))  d->channel_width_mhz = 80;
            else if (strstr(mhz_str, "40"))  d->channel_width_mhz = 40;
            else                              d->channel_width_mhz = 20;

            /* Determine standard from rate + mcs + width */
            if (rate_mbps > 600)      d->standard = IFWIFI_STD_AC;
            else if (mcs >= 0)        d->standard = IFWIFI_STD_N;
            else if (rate_mbps > 54)  d->standard = IFWIFI_STD_N;
            else if (d->band == IFWIFI_BAND_5GHZ) d->standard = IFWIFI_STD_A;
            else if (rate_mbps > 11)  d->standard = IFWIFI_STD_G;
            else                      d->standard = IFWIFI_STD_B;
        }
        else if (strncmp(s, "rx bitrate:", 11) == 0) {
            float rate_mbps = 0;
            int   mcs = -1;
            sscanf(s + 11, "%f MBit/s MCS %d", &rate_mbps, &mcs);
            d->rx_bitrate_100bps = (unsigned long)(rate_mbps * 10000);
            d->rx_mcs = mcs;
        }
    }
    pclose(fp);
    return 0;
}

/* ============================================================================
 * SOURCE 3: `iw dev <iface> station dump`
 *
 * For a STA (client), this shows stats for the connected AP.
 * Example output:
 *   Station aa:bb:cc:dd:ee:ff (on wlan0)
 *           inactive time:  200 ms
 *           rx bytes:   87654321
 *           rx packets: 654321
 *           tx bytes:   12345678
 *           tx packets: 98765
 *           tx retries: 1234
 *           tx failed:  56
 *           rx drop misc: 78
 *           signal:  -65 [-65] dBm
 *           tx bitrate: 300.0 MBit/s MCS 15
 *           rx bitrate: 300.0 MBit/s MCS 15
 *           beacon loss: 0
 * ========================================================================== */
static int read_iw_station(ifWifiData *d)
{
    FILE   *fp;
    char    cmd[128];
    char    line[512];

    snprintf(cmd, sizeof(cmd),
             "iw dev %s station dump 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);
        unsigned long long ull_val;
        unsigned long ul_val;

        if (sscanf(s, "rx bytes: %llu",   &ull_val) == 1) d->rx_bytes      = ull_val;
        else if (sscanf(s, "rx packets: %llu", &ull_val) == 1) d->rx_packets = ull_val;
        else if (sscanf(s, "tx bytes: %llu",   &ull_val) == 1) d->tx_bytes   = ull_val;
        else if (sscanf(s, "tx packets: %llu", &ull_val) == 1) d->tx_packets = ull_val;
        else if (sscanf(s, "tx retries: %lu",  &ul_val)  == 1) d->tx_retries = ul_val;
        else if (sscanf(s, "tx failed: %lu",   &ul_val)  == 1) d->tx_failed  = ul_val;
        else if (sscanf(s, "rx drop misc: %lu",&ul_val)  == 1) d->rx_drop_misc = ul_val;
        else if (sscanf(s, "beacon loss: %lu", &ul_val)  == 1) d->beacon_loss = ul_val;
    }
    pclose(fp);
    return 0;
}

/* ============================================================================
 * DISCOVER WiFi interfaces from /proc/net/wireless
 * Returns count of interfaces found.
 * ========================================================================== */
static int discover_wifi_interfaces(char names[][IFNAMSIZ], int max)
{
    FILE *fp;
    char  line[256];
    int   count  = 0;
    int   lineno = 0;

    fp = fopen("/proc/net/wireless", "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp) && count < max) {
        lineno++;
        if (lineno <= 2) continue;
        char iface[IFNAMSIZ];
        if (sscanf(line, " %15[^:]:", iface) == 1) {
            strncpy(names[count], iface, IFNAMSIZ - 1);
            names[count][IFNAMSIZ - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    return count;
}

/* ============================================================================
 * ifIndex lookup — use if_nametoindex() (POSIX)
 * ========================================================================== */
static long get_ifindex(const char *ifname)
{
    unsigned int idx = if_nametoindex(ifname);
    return idx ? (long)idx : -1;
}

/* ============================================================================
 * PUBLIC API
 * ========================================================================== */

/*
 * ifWifi_load_data()
 * Refresh the cached wifi_table[] from the kernel.
 * Called by the SNMP agent cache handler every IFWIFI_CACHE_TIMEOUT seconds.
 */
int ifWifi_load_data(void)
{
    char   ifaces[32][IFNAMSIZ];
    int    n, i;
    time_t now = time(NULL);

    /* Cache still fresh? */
    if (wifi_loaded && (now - wifi_loaded) < IFWIFI_CACHE_TIMEOUT)
        return wifi_count;

    /* Free old data */
    ifWifi_free_data();

    /* Discover interfaces */
    n = discover_wifi_interfaces(ifaces, 32);
    if (n == 0) {
        wifi_loaded = now;
        return 0;
    }

    wifi_table = calloc(n, sizeof(ifWifiData));
    if (!wifi_table) return -1;

    wifi_count = 0;
    for (i = 0; i < n; i++) {
        ifWifiData *d = &wifi_table[wifi_count];
        strncpy(d->ifName, ifaces[i], IFNAMSIZ - 1);

        d->ifIndex = get_ifindex(d->ifName);
        if (d->ifIndex < 0) continue;   /* interface disappeared */

        /* Default MCS to -1 (not applicable) */
        d->tx_mcs = d->rx_mcs = -1;
        d->auth_alg = IFWIFI_AUTH_NONE;

        /* Collect data from all 3 sources */
        read_proc_wireless(d);
        read_iw_link(d);
        read_iw_station(d);

        d->last_updated = now;
        wifi_count++;

        DEBUGMSGTL(("ifWifi", "Loaded %s: ifIndex=%ld signal=%d ssid=%s\n",
                    d->ifName, d->ifIndex, d->signal_dbm, d->ssid));
    }

    wifi_loaded = now;
    return wifi_count;
}

/*
 * ifWifi_get_by_ifindex()
 * Returns a pointer to the cached row for the given ifIndex.
 * Refreshes cache if stale.
 */
ifWifiData *ifWifi_get_by_ifindex(long ifIndex)
{
    int i;
    ifWifi_load_data();
    for (i = 0; i < wifi_count; i++) {
        if (wifi_table[i].ifIndex == ifIndex)
            return &wifi_table[i];
    }
    return NULL;
}

/*
 * ifWifi_free_data()
 */
void ifWifi_free_data(void)
{
    if (wifi_table) {
        free(wifi_table);
        wifi_table  = NULL;
        wifi_count  = 0;
        wifi_loaded = 0;
    }
}
