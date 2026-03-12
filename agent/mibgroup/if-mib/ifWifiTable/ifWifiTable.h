/*
 * ifWifiTable.h
 *
 * WiFi statistics extension for IF-MIB::ifTable
 * Net-SNMP 5.9.4 / OpenWrt 24.10 aarch64 musl-libc
 *
 * ══════════════════════════════════════════════════════════════
 * LINKER ERROR FIX — "undefined reference to ifWifi_get_by_ifindex"
 *
 * Root cause:
 *   net-snmp's build system only compiles the .c file whose name
 *   matches the module name given to --with-mib-modules.
 *   So only ifWifiTable.c was compiled; ifWifiTable_data_access.c
 *   was silently skipped → all symbols from it were undefined at link.
 *
 * Fix:
 *   config_require() below tells net-snmp's configure script to
 *   register ifWifiTable_data_access.c as an additional source file
 *   for this module. The macro MUST be at file scope (not inside a
 *   comment or #if block) so the raw-text scanner in configure finds it.
 *
 *   Canonical reference — net-snmp's own if-mib/ifTable/ifTable.h:
 *     config_require(if-mib/ifTable/ifTable_data_access)
 *     config_require(if-mib/ifTable/ifTable_interface)
 *
 * ══════════════════════════════════════════════════════════════
 * COMPILE ERROR FIX — "IFNAMSIZ undeclared here (not in a function)"
 *
 * Root cause:
 *   mib_module_includes.h includes this header at file scope in
 *   agent_read_config.c before any function body. IFNAMSIZ (<net/if.h>),
 *   time_t (<time.h>), and uint64_t (<stdint.h>) must be pulled in
 *   by THIS header — they cannot rely on the .c file's includes.
 * ══════════════════════════════════════════════════════════════
 */

/*
 * config_require — MUST be outside #ifndef guard so net-snmp's
 * configure scanner (a raw grep) always finds it.
 *
 * Tells the build system: also compile ifWifiTable_data_access.c
 */
config_require(if-mib/ifWifiTable/ifWifiTable_data_access)

#ifndef IFWIFITABLE_H
#define IFWIFITABLE_H

/* ── System headers required at file scope ────────────────────────────── */
#include <net/if.h>     /* IFNAMSIZ — Linux network interface name size */
#include <time.h>       /* time_t   — last_updated field in struct      */
#include <stdint.h>     /* uint32_t, uint64_t — portable counter types  */

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
#define IFWIFI_STD_N                    4   /* WiFi 4  HT   */
#define IFWIFI_STD_AC                   5   /* WiFi 5  VHT  */
#define IFWIFI_STD_AX                   6   /* WiFi 6  HE   */
#define IFWIFI_STD_BE                   7   /* WiFi 7  EHT  */

/* ── Authentication algorithm enumeration values ───────────────────────── */
#define IFWIFI_AUTH_NONE                0
#define IFWIFI_AUTH_OPEN                1
#define IFWIFI_AUTH_WPA2_PERSONAL       2
#define IFWIFI_AUTH_WPA2_ENTERPRISE     3
#define IFWIFI_AUTH_WPA3_PERSONAL       4
#define IFWIFI_AUTH_WPA3_ENTERPRISE     5

/* ── Cache TTL ─────────────────────────────────────────────────────────── */
#define IFWIFI_CACHE_TIMEOUT            15  /* seconds between iw calls */

/*
 * ifWifiData — one cached row per wireless interface
 *
 * Row key: ifIndex — same as IF-MIB::ifTable (AUGMENTS ifEntry)
 *
 * uint64_t for Counter64 MIB objects  (avoids 'unsigned long long' warnings)
 * uint32_t for Counter32/Gauge32      (32-bit on all platforms)
 * IFNAMSIZ from <net/if.h>            (always 16 on Linux)
 */
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
    int             standard;           /* IFWIFI_STD_*  */

    /* signal quality */
    int             signal_dbm;
    int             noise_dbm;
    int             snr_db;
    unsigned int    link_quality;
    unsigned int    link_quality_max;

    /* bit rates — Gauge32, units: 100 bps */
    uint32_t        tx_bitrate_100bps;
    uint32_t        rx_bitrate_100bps;
    int             tx_mcs;             /* -1 = legacy (non-HT) rate */
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
    int             connected;          /* 1=true, 2=false (TruthValue) */
    int             auth_alg;           /* IFWIFI_AUTH_* */
    char            pairwise_cipher[17];
    char            group_cipher[17];

    /* internal */
    time_t          last_updated;

} ifWifiData;

/* ── Public API (implemented in ifWifiTable_data_access.c) ────────────── */
void        init_ifWifiTable(void);
void        shutdown_ifWifiTable(void);
int         ifWifi_load_data(void);
ifWifiData *ifWifi_get_by_ifindex(long ifIndex);
void        ifWifi_free_data(void);

#endif /* IFWIFITABLE_H */
