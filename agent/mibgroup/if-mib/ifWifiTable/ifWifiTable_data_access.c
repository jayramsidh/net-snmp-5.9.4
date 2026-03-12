/*
 * ifWifiTable_data_access.c
 *
 * Data collection layer for IFWIFI-MIB
 * Net-SNMP 5.9.4 / OpenWrt 24.10 aarch64 musl-libc compatible
 *
 * FIXES vs original:
 *   - All uint64_t/uint32_t types match the header (no 'unsigned long long')
 *   - sscanf format specifiers updated: %llu → %"SCNu64", %lu → %"SCNu32"
 *   - popen() result checked properly
 *   - strtrim() made static to avoid linker conflicts with other modules
 *   - IFNAMSIZ provided by ifWifiTable.h (which includes <net/if.h>)
 *
 * Data sources (read in this order per interface):
 *   1. /proc/net/wireless   — signal_dbm, noise_dbm, link_quality
 *   2. iw dev <if> link     — ssid, bssid, channel, band, bitrate, mcs
 *   3. iw dev <if> station dump — tx/rx counters, retries, beacon_loss
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>       /* SCNu32, SCNu64, PRIu64 */

#include "ifWifiTable.h"    /* includes <net/if.h>, <time.h>, <stdint.h> */

/* ── Internal list of discovered WiFi interfaces ────────────────────────── */
static ifWifiData  *wifi_table  = NULL;
static int          wifi_count  = 0;
static time_t       wifi_loaded = 0;

/* ============================================================================
 * INTERNAL HELPERS
 * ========================================================================== */

/* Trim leading/trailing whitespace in-place; returns pointer into s */
static char *strtrim(char *s)
{
    char *end;
    if (!s) return s;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return s;
}

/* Parse "aa:bb:cc:dd:ee:ff" into a 6-byte array. Returns 1 on success. */
static int parse_mac(const char *str, unsigned char *mac)
{
    unsigned int b[6];
    int n = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    if (n == 6) {
        int i;
        for (i = 0; i < 6; i++) mac[i] = (unsigned char)b[i];
        return 1;
    }
    return 0;
}

/* Convert frequency in MHz to 802.11 channel number */
static int freq_to_channel(int freq_mhz)
{
    if (freq_mhz == 2484) return 14;
    if (freq_mhz >= 2412 && freq_mhz <= 2472) return (freq_mhz - 2412) / 5 + 1;
    if (freq_mhz >= 5180 && freq_mhz <= 5825) return (freq_mhz - 5000) / 5;
    if (freq_mhz >= 5955 && freq_mhz <= 7115) return (freq_mhz - 5955) / 5 + 1;
    return 0;
}

/* Map frequency in MHz to IFWIFI_BAND_* */
static int freq_to_band(int freq_mhz)
{
    if (freq_mhz >= 2400 && freq_mhz < 2500) return IFWIFI_BAND_2GHZ;
    if (freq_mhz >= 5000 && freq_mhz < 5950) return IFWIFI_BAND_5GHZ;
    if (freq_mhz >= 5950 && freq_mhz < 7200) return IFWIFI_BAND_6GHZ;
    if (freq_mhz >= 57000)                    return IFWIFI_BAND_60GHZ;
    return IFWIFI_BAND_UNKNOWN;
}

/* ============================================================================
 * SOURCE 1 — /proc/net/wireless
 *
 * Format (skip 2 header lines):
 *   phy0-sta0: 0000  55.  -56.  -95.    0    0    0    0    0    0
 *              stat  lq   sig   noise  ...
 *
 * Values with trailing '.' are in dBm.
 * ========================================================================== */
static int read_proc_wireless(ifWifiData *d)
{
    FILE *fp;
    char  line[256];
    char  iface[IFNAMSIZ];
    int   status, lineno = 0;
    float lq, sig, noise;

    fp = fopen("/proc/net/wireless", "r");
    if (!fp) {
        DEBUGMSGTL(("ifWifi", "Cannot open /proc/net/wireless\n"));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (lineno <= 2) continue;   /* skip 2 header lines */

        if (sscanf(line, " %15[^:]: %x %f. %f. %f.",
                   iface, &status, &lq, &sig, &noise) >= 4) {
            if (strcmp(iface, d->ifName) == 0) {
                d->link_quality     = (unsigned int)lq;
                d->link_quality_max = 70;  /* typical driver max */
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
    return -1;
}

/* ============================================================================
 * SOURCE 2 — `iw dev <iface> link`
 *
 * Example output when connected:
 *   Connected to aa:bb:cc:dd:ee:ff (on phy0-sta0)
 *         SSID: MyNetwork
 *         freq: 5240
 *         signal: -65 dBm
 *         rx bitrate: 300.0 MBit/s MCS 15 40MHz short GI
 *         tx bitrate: 270.0 MBit/s MCS 13 40MHz short GI
 * ========================================================================== */
static int read_iw_link(ifWifiData *d)
{
    FILE *fp;
    char  cmd[128];
    char  line[512];
    int   freq = 0;

    snprintf(cmd, sizeof(cmd), "iw dev %s link 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return -1;

    d->connected = 2;   /* TruthValue false */
    memset(d->bssid, 0, 6);
    d->ssid[0]    = '\0';
    d->tx_mcs     = -1;
    d->rx_mcs     = -1;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);

        if (strncmp(s, "Connected to", 12) == 0) {
            char mac_str[18] = {0};
            if (sscanf(s, "Connected to %17s", mac_str) == 1) {
                parse_mac(mac_str, d->bssid);
                d->connected = 1;   /* TruthValue true */
            }
        }
        else if (strncmp(s, "SSID:", 5) == 0) {
            strncpy(d->ssid, strtrim(s + 5), 32);
            d->ssid[32] = '\0';
        }
        else if (strncmp(s, "freq:", 5) == 0) {
            sscanf(s + 5, "%d", &freq);
            d->channel = freq_to_channel(freq);
            d->band    = freq_to_band(freq);
        }
        else if (strncmp(s, "signal:", 7) == 0) {
            sscanf(s + 7, "%d", &d->signal_dbm);
        }
        else if (strncmp(s, "tx bitrate:", 11) == 0) {
            float rate_mbps = 0.0f;
            int   mcs       = -1;
            char  mhz_str[16] = {0};

            /* e.g.: "270.0 MBit/s MCS 13 40MHz short GI" */
            sscanf(s + 11, "%f MBit/s MCS %d %15s", &rate_mbps, &mcs, mhz_str);
            d->tx_bitrate_100bps = (uint32_t)(rate_mbps * 10000.0f);
            d->tx_mcs            = mcs;

            /* Infer channel width */
            if      (strstr(mhz_str, "160")) d->channel_width_mhz = 160;
            else if (strstr(mhz_str, "80"))  d->channel_width_mhz = 80;
            else if (strstr(mhz_str, "40"))  d->channel_width_mhz = 40;
            else                              d->channel_width_mhz = 20;

            /* Infer 802.11 standard */
            if      (rate_mbps > 600)              d->standard = IFWIFI_STD_AC;
            else if (mcs >= 0)                     d->standard = IFWIFI_STD_N;
            else if (d->band == IFWIFI_BAND_5GHZ)  d->standard = IFWIFI_STD_A;
            else if (rate_mbps > 11.0f)            d->standard = IFWIFI_STD_G;
            else                                   d->standard = IFWIFI_STD_B;
        }
        else if (strncmp(s, "rx bitrate:", 11) == 0) {
            float rate_mbps = 0.0f;
            int   mcs       = -1;
            sscanf(s + 11, "%f MBit/s MCS %d", &rate_mbps, &mcs);
            d->rx_bitrate_100bps = (uint32_t)(rate_mbps * 10000.0f);
            d->rx_mcs            = mcs;
        }
    }
    pclose(fp);
    return 0;
}

/* ============================================================================
 * SOURCE 3 — `iw dev <iface> station dump`
 *
 * For a STA (client), shows counters for the associated AP.
 * Example:
 *   Station aa:bb:cc:dd:ee:ff (on phy0-sta0)
 *           rx bytes:   87654321
 *           rx packets: 654321
 *           tx bytes:   12345678
 *           tx packets: 98765
 *           tx retries: 1234
 *           tx failed:  56
 *           rx drop misc: 78
 *           beacon loss: 0
 * ========================================================================== */
static int read_iw_station(ifWifiData *d)
{
    FILE    *fp;
    char     cmd[128];
    char     line[512];
    uint64_t u64;
    uint32_t u32;

    snprintf(cmd, sizeof(cmd),
             "iw dev %s station dump 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);

        /* Use SCNu64/SCNu32 from <inttypes.h> — correct on all platforms */
        if      (sscanf(s, "rx bytes: %"SCNu64,    &u64) == 1) d->rx_bytes    = u64;
        else if (sscanf(s, "rx packets: %"SCNu64,  &u64) == 1) d->rx_packets  = u64;
        else if (sscanf(s, "tx bytes: %"SCNu64,    &u64) == 1) d->tx_bytes    = u64;
        else if (sscanf(s, "tx packets: %"SCNu64,  &u64) == 1) d->tx_packets  = u64;
        else if (sscanf(s, "tx retries: %"SCNu32,  &u32) == 1) d->tx_retries  = u32;
        else if (sscanf(s, "tx failed: %"SCNu32,   &u32) == 1) d->tx_failed   = u32;
        else if (sscanf(s, "rx drop misc: %"SCNu32,&u32) == 1) d->rx_drop_misc= u32;
        else if (sscanf(s, "beacon loss: %"SCNu32, &u32) == 1) d->beacon_loss = u32;
    }
    pclose(fp);
    return 0;
}

/* ============================================================================
 * DISCOVER WiFi interfaces from /proc/net/wireless
 * Returns count; fills names[][] with interface names.
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
        char iface[IFNAMSIZ];
        lineno++;
        if (lineno <= 2) continue;
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
 * PUBLIC API
 * ========================================================================== */

/*
 * ifWifi_load_data()
 *
 * Refresh the cached wifi_table[] from the kernel.
 * Honours IFWIFI_CACHE_TIMEOUT — does nothing if data is fresh.
 * Called automatically by ifWifi_get_by_ifindex().
 */
int ifWifi_load_data(void)
{
    char   ifaces[32][IFNAMSIZ];
    int    n, i;
    time_t now = time(NULL);

    /* Cache still fresh? */
    if (wifi_loaded && (now - wifi_loaded) < IFWIFI_CACHE_TIMEOUT)
        return wifi_count;

    ifWifi_free_data();

    n = discover_wifi_interfaces(ifaces, 32);
    if (n <= 0) {
        wifi_loaded = now;
        return 0;
    }

    wifi_table = (ifWifiData *)calloc((size_t)n, sizeof(ifWifiData));
    if (!wifi_table) return -1;

    wifi_count = 0;
    for (i = 0; i < n; i++) {
        ifWifiData   *d   = &wifi_table[wifi_count];
        unsigned int  idx = if_nametoindex(ifaces[i]);

        if (!idx) continue;   /* interface disappeared */

        strncpy(d->ifName, ifaces[i], IFNAMSIZ - 1);
        d->ifIndex = (long)idx;
        d->tx_mcs  = -1;
        d->rx_mcs  = -1;
        d->auth_alg = IFWIFI_AUTH_NONE;

        read_proc_wireless(d);
        read_iw_link(d);
        read_iw_station(d);

        d->last_updated = now;
        wifi_count++;

        DEBUGMSGTL(("ifWifi",
                    "Loaded iface=%s ifIndex=%ld signal=%d ssid='%s'\n",
                    d->ifName, d->ifIndex, d->signal_dbm, d->ssid));
    }

    wifi_loaded = now;
    return wifi_count;
}

/*
 * ifWifi_get_by_ifindex()
 * Returns pointer to cached row, or NULL if not a WiFi interface.
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
 * Free cache; called by shutdown_ifWifiTable() and at start of reload.
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
