/*
 * ifWifiTable_data_access.c
 *
 * Data collection for IFWIFI-MIB
 * Net-SNMP 5.9.4 / OpenWrt 24.10 aarch64 musl-libc
 *
 * ROOT CAUSE FIX — "No Such Instance" on all OIDs:
 *
 *   /proc/net/wireless does NOT exist on this kernel.
 *   The old discover_wifi_interfaces() read that file → found 0 interfaces
 *   → empty table → every OID returned "No Such Instance".
 *
 *   This version uses ONLY `iw dev` commands for everything:
 *     iw dev                      → discover all WiFi interfaces
 *     iw dev <iface> link         → SSID, BSSID, freq, signal, bitrate, MCS
 *     iw dev <iface> info         → channel, width, band
 *     iw dev <iface> station dump → TX/RX counters, signal, retries
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "ifWifiTable.h"

static ifWifiData  *wifi_table  = NULL;
static int          wifi_count  = 0;
static time_t       wifi_loaded = 0;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

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

static int parse_mac(const char *str, unsigned char *mac)
{
    unsigned int b[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6) {
        int i;
        for (i = 0; i < 6; i++) mac[i] = (unsigned char)b[i];
        return 1;
    }
    return 0;
}

static int freq_to_channel(int f)
{
    if (f == 2484) return 14;
    if (f >= 2412 && f <= 2472) return (f - 2412) / 5 + 1;
    if (f >= 5180 && f <= 5825) return (f - 5000) / 5;
    if (f >= 5955 && f <= 7115) return (f - 5955) / 5 + 1;
    return 0;
}

static int freq_to_band(int f)
{
    if (f >= 2400 && f < 2500) return IFWIFI_BAND_2GHZ;
    if (f >= 5000 && f < 5950) return IFWIFI_BAND_5GHZ;
    if (f >= 5950 && f < 7200) return IFWIFI_BAND_6GHZ;
    if (f >= 57000)             return IFWIFI_BAND_60GHZ;
    return IFWIFI_BAND_UNKNOWN;
}

/* ── Interface discovery via `iw dev` ────────────────────────────────────
 *
 * Parses:
 *   phy#0
 *       Interface phy0-sta0       ← name
 *           ifindex 13
 *           type managed          ← accept managed/AP/mesh/IBSS
 *
 * Returns count of discovered WiFi interface names.
 * ──────────────────────────────────────────────────────────────────────── */
static int discover_wifi_interfaces(char names[][IFNAMSIZ], int max)
{
    FILE *fp;
    char  line[256];
    int   count       = 0;
    char  cur[IFNAMSIZ] = {0};
    int   is_wifi     = 0;

    fp = popen("iw dev 2>/dev/null", "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp) && count < max) {
        char *s = strtrim(line);

        if (strncmp(s, "Interface ", 10) == 0) {
            /* Save previous if it was a WiFi type */
            if (cur[0] && is_wifi) {
                strncpy(names[count++], cur, IFNAMSIZ - 1);
            }
            strncpy(cur, s + 10, IFNAMSIZ - 1);
            cur[IFNAMSIZ - 1] = '\0';
            is_wifi = 0;
        }
        else if (strncmp(s, "type ", 5) == 0) {
            char *t = s + 5;
            if (strncmp(t, "managed", 7) == 0 ||
                strncmp(t, "AP",      2) == 0 ||
                strncmp(t, "mesh",    4) == 0 ||
                strncmp(t, "IBSS",    4) == 0)
                is_wifi = 1;
        }
    }
    /* Last entry */
    if (cur[0] && is_wifi && count < max)
        strncpy(names[count++], cur, IFNAMSIZ - 1);

    pclose(fp);
    DEBUGMSGTL(("ifWifi", "discover: %d WiFi interfaces found\n", count));
    return count;
}

/* ── `iw dev <iface> link` ───────────────────────────────────────────────
 *
 * Real output from this device:
 *   Connected to f0:ed:b8:94:d1:83 (on phy0-sta0)
 *       SSID: JioFiber-4q6G6
 *       freq: 2462.0
 *       signal: -55 dBm
 *       rx bitrate: 14.4 MBit/s MCS 8 short GI
 * ──────────────────────────────────────────────────────────────────────── */
static void read_iw_link(ifWifiData *d)
{
    FILE *fp;
    char  cmd[128], line[512];

    snprintf(cmd, sizeof(cmd), "iw dev %s link 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return;

    d->connected = 2; /* false */
    d->tx_mcs    = -1;
    d->rx_mcs    = -1;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);

        if (strncmp(s, "Connected to", 12) == 0) {
            char mac[18] = {0};
            sscanf(s, "Connected to %17s", mac);
            parse_mac(mac, d->bssid);
            d->connected = 1;
        }
        else if (strncmp(s, "SSID:", 5) == 0) {
            strncpy(d->ssid, strtrim(s + 5), 32);
            d->ssid[32] = '\0';
        }
        else if (strncmp(s, "freq:", 5) == 0) {
            float f = 0.0f;
            sscanf(s + 5, "%f", &f);
            int fi = (int)f;
            d->channel = freq_to_channel(fi);
            d->band    = freq_to_band(fi);
        }
        else if (strncmp(s, "signal:", 7) == 0) {
            sscanf(s + 7, "%d", &d->signal_dbm);
        }
        else if (strncmp(s, "tx bitrate:", 11) == 0) {
            float r = 0.0f; int mcs = -1; char w[16] = {0};
            sscanf(s + 11, "%f MBit/s MCS %d %15s", &r, &mcs, w);
            d->tx_bitrate_100bps = (uint32_t)(r * 10000.0f);
            d->tx_mcs = mcs;
            if      (strstr(w, "160")) d->channel_width_mhz = 160;
            else if (strstr(w, "80"))  d->channel_width_mhz = 80;
            else if (strstr(w, "40"))  d->channel_width_mhz = 40;
            else                       d->channel_width_mhz = 20;
            if      (r > 600.0f)                   d->standard = IFWIFI_STD_AC;
            else if (mcs >= 0)                     d->standard = IFWIFI_STD_N;
            else if (d->band == IFWIFI_BAND_5GHZ)  d->standard = IFWIFI_STD_A;
            else if (r > 11.0f)                    d->standard = IFWIFI_STD_G;
            else                                   d->standard = IFWIFI_STD_B;
        }
        else if (strncmp(s, "rx bitrate:", 11) == 0) {
            float r = 0.0f; int mcs = -1;
            sscanf(s + 11, "%f MBit/s MCS %d", &r, &mcs);
            d->rx_bitrate_100bps = (uint32_t)(r * 10000.0f);
            d->rx_mcs = mcs;
        }
    }
    pclose(fp);
}

/* ── `iw dev <iface> info` — fills channel/width if link didn't ─────────── */
static void read_iw_info(ifWifiData *d)
{
    FILE *fp;
    char  cmd[128], line[512];

    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);
        int ch = 0, freq = 0, width = 0;
        if (sscanf(s, "channel %d (%d MHz), width: %d MHz",
                   &ch, &freq, &width) >= 2) {
            if (d->channel == 0) {
                d->channel = ch ? ch : freq_to_channel(freq);
                d->band    = freq_to_band(freq);
            }
            if (d->channel_width_mhz == 0 && width > 0)
                d->channel_width_mhz = width;
        }
    }
    pclose(fp);
}

/* ── `iw dev <iface> station dump` — counters + signal ──────────────────── */
static void read_iw_station(ifWifiData *d)
{
    FILE    *fp;
    char     cmd[128], line[512];
    uint64_t u64;
    uint32_t u32;
    int      ival;

    snprintf(cmd, sizeof(cmd),
             "iw dev %s station dump 2>/dev/null", d->ifName);
    fp = popen(cmd, "r");
    if (!fp) return;

    while (fgets(line, sizeof(line), fp)) {
        char *s = strtrim(line);

        if      (sscanf(s, "rx bytes: %"SCNu64,     &u64) == 1) d->rx_bytes     = u64;
        else if (sscanf(s, "rx packets: %"SCNu64,   &u64) == 1) d->rx_packets   = u64;
        else if (sscanf(s, "tx bytes: %"SCNu64,     &u64) == 1) d->tx_bytes     = u64;
        else if (sscanf(s, "tx packets: %"SCNu64,   &u64) == 1) d->tx_packets   = u64;
        else if (sscanf(s, "tx retries: %"SCNu32,   &u32) == 1) d->tx_retries   = u32;
        else if (sscanf(s, "tx failed: %"SCNu32,    &u32) == 1) d->tx_failed    = u32;
        else if (sscanf(s, "rx drop misc: %"SCNu32, &u32) == 1) d->rx_drop_misc = u32;
        else if (sscanf(s, "beacon loss: %"SCNu32,  &u32) == 1) d->beacon_loss  = u32;
        else if (sscanf(s, "signal: %d", &ival) == 1) {
            /* station dump signal is more accurate than link signal */
            d->signal_dbm = ival;
            /* Estimate noise floor (typical values; kernel doesn't expose it) */
            d->noise_dbm  = (d->band == IFWIFI_BAND_5GHZ) ? -95 : -90;
            d->snr_db     = d->signal_dbm - d->noise_dbm;
            if (d->snr_db < 0) d->snr_db = 0;
            /* Map to 0-70 link quality scale */
            d->link_quality_max = 70;
            d->link_quality     = (unsigned int)(70 + d->signal_dbm);
            if ((int)d->link_quality < 0) d->link_quality = 0;
            if (d->link_quality > 70)     d->link_quality = 70;
        }
    }
    pclose(fp);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int ifWifi_load_data(void)
{
    char   ifaces[32][IFNAMSIZ];
    int    n, i;
    time_t now = time(NULL);

    if (wifi_loaded && (now - wifi_loaded) < IFWIFI_CACHE_TIMEOUT)
        return wifi_count;

    ifWifi_free_data();

    n = discover_wifi_interfaces(ifaces, 32);
    if (n <= 0) {
        snmp_log(LOG_WARNING,
                 "ifWifi: no WiFi interfaces found via 'iw dev'\n");
        wifi_loaded = now;
        return 0;
    }

    wifi_table = (ifWifiData *)calloc((size_t)n, sizeof(ifWifiData));
    if (!wifi_table) return -1;

    wifi_count = 0;
    for (i = 0; i < n; i++) {
        ifWifiData   *d   = &wifi_table[wifi_count];
        unsigned int  idx = if_nametoindex(ifaces[i]);

        if (!idx) continue;

        strncpy(d->ifName, ifaces[i], IFNAMSIZ - 1);
        d->ifIndex           = (long)idx;
        d->tx_mcs            = -1;
        d->rx_mcs            = -1;
        d->auth_alg          = IFWIFI_AUTH_NONE;
        d->channel_width_mhz = 20;

        read_iw_link(d);
        read_iw_info(d);
        read_iw_station(d);

        d->last_updated = now;
        wifi_count++;

        snmp_log(LOG_INFO,
                 "ifWifi: %s ifIndex=%ld connected=%d ssid='%s' "
                 "signal=%d band=%d ch=%d\n",
                 d->ifName, d->ifIndex, d->connected,
                 d->ssid, d->signal_dbm, d->band, d->channel);
    }

    wifi_loaded = now;
    return wifi_count;
}

ifWifiData *ifWifi_get_by_ifindex(long ifIndex)
{
    int i;
    ifWifi_load_data();
    for (i = 0; i < wifi_count; i++)
        if (wifi_table[i].ifIndex == ifIndex)
            return &wifi_table[i];
    return NULL;
}

void ifWifi_free_data(void)
{
    if (wifi_table) {
        free(wifi_table);
        wifi_table  = NULL;
        wifi_count  = 0;
        wifi_loaded = 0;
    }
}
