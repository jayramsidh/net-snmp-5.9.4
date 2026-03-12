/*
 * ifWifiTable.h
 *
 * WiFi statistics extension for IF-MIB::ifTable
 * Net-SNMP 5.9.4 / OpenWrt 24.10 aarch64 musl-libc
 *
 * These macros must remain at file scope so Net-SNMP's configure
 * scanner can detect them.
 */

config_add_mib(IFWIFI-MIB)
config_require(if-mib/ifWifiTable/ifWifiTable_data_access)

#ifndef IFWIFITABLE_H
#define IFWIFITABLE_H

#include <net/if.h>
#include <time.h>
#include <stdint.h>

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
#define COLUMN_IFWIFIAUTHALG            25
#define COLUMN_IFWIFIPAIRWISECIPHER     26
#define COLUMN_IFWIFIGROUPCIPHER        27

/* ── Band enumeration values ───────────────────────────────────────────── */
#define IFWIFI_BAND_UNKNOWN             0
#define IFWIFI_BAND_2GHZ                1
#define IFWIFI_BAND_5GHZ                2
#define IFWIFI_BAND_6GHZ                3
#define IFWIFI_BAND_60GHZ               4

/* ── IEEE 802.11 standard enumeration values ───────────────────────────── */
#define IFWIFI_STD_UNKNOWN              0
#define IFWIFI_STD_B                    1
#define IFWIFI_STD_G                    2
#define IFWIFI_STD_A                    3
#define IFWIFI_STD_N                    4
#define IFWIFI_STD_AC                   5
#define IFWIFI_STD_AX                   6
#define IFWIFI_STD_BE                   7

/* ── Authentication algorithm enumeration values ───────────────────────── */
#define IFWIFI_AUTH_NONE                0
#define IFWIFI_AUTH_OPEN                1
#define IFWIFI_AUTH_WPA2_PERSONAL       2
#define IFWIFI_AUTH_WPA2_ENTERPRISE     3
#define IFWIFI_AUTH_WPA3_PERSONAL       4
#define IFWIFI_AUTH_WPA3_ENTERPRISE     5

/* ── Cache TTL ─────────────────────────────────────────────────────────── */
#define IFWIFI_CACHE_TIMEOUT            15

/*
 * ifWifiData — one cached row per wireless interface
 *
 * Row key: ifIndex — same as IF-MIB::ifTable (AUGMENTS ifEntry)
 */
typedef struct ifWifiData_s {
    /* identity */
    long            ifIndex;
    char            ifName[IFNAMSIZ];

    /* radio / PHY */
    char            ssid[33];
    unsigned char   bssid[6];
    int             channel;
    int             channel_width_mhz;
    int             band;
    int             standard;

    /* signal quality */
    int             signal_dbm;
    int             noise_dbm;
    int             snr_db;
    unsigned int    link_quality;
    unsigned int    link_quality_max;

    /* bit rates — Gauge32, units: 100 bps */
    uint32_t        tx_bitrate_100bps;
    uint32_t        rx_bitrate_100bps;
    int             tx_mcs;     /* -1 = legacy */
    int             rx_mcs;

    /* packet/byte counters — Counter64 */
    uint64_t        tx_packets;
    uint64_t        rx_packets;
    uint64_t        tx_bytes;
    uint64_t        rx_bytes;

    /* error counters — Counter32 */
    uint32_t        tx_retries;
    uint32_t        tx_failed;
    uint32_t        rx_drop_misc;
    uint32_t        beacon_loss;

    /* association state */
    int             connected;  /* TruthValue: 1=true, 2=false */
    int             auth_alg;   /* IFWIFI_AUTH_* */
    char            pairwise_cipher[17];
    char            group_cipher[17];

    /* internal */
    time_t          last_updated;
} ifWifiData;

/* ── Public API ────────────────────────────────────────────────────────── */
void        init_ifWifiTable(void);
void        shutdown_ifWifiTable(void);
int         ifWifi_load_data(void);
ifWifiData *ifWifi_get_by_ifindex(long ifIndex);
void        ifWifi_free_data(void);

#endif /* IFWIFITABLE_H */
