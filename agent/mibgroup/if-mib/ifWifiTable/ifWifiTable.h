/*
 * ifWifiTable.h
 *
 * WiFi statistics extension for IF-MIB::ifTable
 * Net-SNMP V5-9-3-branch compatible
 *
 * This module AUGMENTS ifTable — it shares the same ifIndex row key.
 * One row exists for each wireless network interface detected on the host.
 *
 * Data sources (Linux):
 *   /proc/net/wireless        — signal, noise, link quality
 *   iw dev <iface> link       — SSID, BSSID, bitrate, MCS
 *   iw dev <iface> station dump — tx/rx packets/bytes/retries/failed
 *   iw dev <iface> info       — channel, width, band
 */

#ifndef IFWIFITABLE_H
#define IFWIFITABLE_H

/* ── Column OID numbers (relative to ifWifiEntry) ─────────────────────── */
#define COLUMN_IFWIFISSID               1
#define COLUMN_IFWIFIBSSID              2
#define COLUMN_IFWIFICHANNEL            3
#define COLUMN_IFWIFICHANNELWIDTH       4
#define COLUMN_IFWIFIBAND               5
#define COLUMN_IFWIFISTANDARD           6
#define COLUMN_IFWIFISIGNALDBM          7
#define COLUMN_IFWIFINOISEDMB           8
#define COLUMN_IFWIFISNR                9
#define COLUMN_IFWIFILINKQUALITY        10
#define COLUMN_IFWIFILINKQUALITYMAX     11
#define COLUMN_IFWIFITXBITRATE          12
#define COLUMN_IFWIFIRXBITRATE          13
#define COLUMN_IFWIFITXMCS              14
#define COLUMN_IFWIFIRXMCS              15
#define COLUMN_IFWIFITXPACKETS          16
#define COLUMN_IFWIFIRXPACKETS          17
#define COLUMN_IFWIFITXBYTES            18
#define COLUMN_IFWIFIRXBYTES            19
#define COLUMN_IFWIFITXRETRIES          20
#define COLUMN_IFWIFITXFAILED           21
#define COLUMN_IFWIFIRXDROPMISC         22
#define COLUMN_IFWIFIBEACONLOSS         23
#define COLUMN_IFWIFICONNECTED          24
#define COLUMN_IFWIFIAAUTHALG           25
#define COLUMN_IFWIFIPAIRWISECIPHER     26
#define COLUMN_IFWIFIGROUPCIPHER        27

/* ── Band enumeration ──────────────────────────────────────────────────── */
#define IFWIFI_BAND_UNKNOWN             0
#define IFWIFI_BAND_2GHZ                1
#define IFWIFI_BAND_5GHZ                2
#define IFWIFI_BAND_6GHZ                3
#define IFWIFI_BAND_60GHZ               4

/* ── Standard enumeration ─────────────────────────────────────────────── */
#define IFWIFI_STD_UNKNOWN              0
#define IFWIFI_STD_B                    1
#define IFWIFI_STD_G                    2
#define IFWIFI_STD_A                    3
#define IFWIFI_STD_N                    4   /* WiFi 4 */
#define IFWIFI_STD_AC                   5   /* WiFi 5 */
#define IFWIFI_STD_AX                   6   /* WiFi 6/6E */
#define IFWIFI_STD_BE                   7   /* WiFi 7 */

/* ── Auth algorithm enumeration ────────────────────────────────────────── */
#define IFWIFI_AUTH_NONE                0
#define IFWIFI_AUTH_OPEN                1
#define IFWIFI_AUTH_WPA2_PERSONAL       2
#define IFWIFI_AUTH_WPA2_ENTERPRISE     3
#define IFWIFI_AUTH_WPA3_PERSONAL       4
#define IFWIFI_AUTH_WPA3_ENTERPRISE     5

/* ── Data structure for one WiFi interface row ─────────────────────────── */
typedef struct ifWifiData_s {
    /* identity */
    long            ifIndex;
    char            ifName[IFNAMSIZ];

    /* radio / PHY */
    char            ssid[33];           /* max 32 chars + NUL */
    unsigned char   bssid[6];
    int             channel;
    int             channel_width_mhz;
    int             band;               /* IFWIFI_BAND_* */
    int             standard;           /* IFWIFI_STD_* */

    /* signal */
    int             signal_dbm;
    int             noise_dbm;
    int             snr_db;
    unsigned int    link_quality;
    unsigned int    link_quality_max;

    /* rates */
    unsigned long   tx_bitrate_100bps;  /* in units of 100bps */
    unsigned long   rx_bitrate_100bps;
    int             tx_mcs;             /* -1 = legacy rate */
    int             rx_mcs;

    /* counters */
    unsigned long long tx_packets;
    unsigned long long rx_packets;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    unsigned long   tx_retries;
    unsigned long   tx_failed;
    unsigned long   rx_drop_misc;
    unsigned long   beacon_loss;

    /* association */
    int             connected;          /* 1=true, 2=false (TruthValue) */
    int             auth_alg;           /* IFWIFI_AUTH_* */
    char            pairwise_cipher[17];
    char            group_cipher[17];

    /* internal */
    time_t          last_updated;
} ifWifiData;

/* ── Cache TTL (seconds between iw calls) ─────────────────────────────── */
#define IFWIFI_CACHE_TIMEOUT    15

/* ── Public API ────────────────────────────────────────────────────────── */

/* Called by net-snmp agent init (snmpd) */
void            init_ifWifiTable(void);
void            shutdown_ifWifiTable(void);

/* Refresh all WiFi interface data from kernel/nl80211 */
int             ifWifi_load_data(void);

/* Lookup a single row by ifIndex */
ifWifiData     *ifWifi_get_by_ifindex(long ifIndex);

/* Free all cached rows */
void            ifWifi_free_data(void);

#endif /* IFWIFITABLE_H */
