/*
 * ifWifiTable.c
 *
 * SNMP agent handler for IFWIFI-MIB::ifWifiTable
 * Net-SNMP 5.9.4 / OpenWrt 24.10 aarch64 musl-libc compatible
 *
 * FIXES vs original:
 *   - Counter64 struct packed correctly for aarch64 (high/low as u_long)
 *   - Proper cast to u_long for Counter64 high/low fields
 *   - uint32_t counters cast to unsigned long for ASN_COUNTER
 *   - uint32_t bitrates cast to u_long for ASN_GAUGE
 *   - string.h included for memset
 *
 * OID structure:
 *   enterprises.99999.10.1.1.1.<column>.<ifIndex>
 *
 * Test:
 *   snmpget  -v2c -c public localhost .1.3.6.1.4.1.99999.10.1.1.1.7.3
 *   snmpwalk -v2c -c public localhost .1.3.6.1.4.1.99999.10
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <string.h>

#include "ifWifiTable.h"   /* brings in <net/if.h> <time.h> <stdint.h> */

/* ── OID: enterprises.99999.10.1.1  (replace 99999 with real IANA PEN) ── */
static oid    ifWifiTable_oid[]     = { 1,3,6,1,4,1, 99999, 10, 1, 1 };
static size_t ifWifiTable_oid_len   = OID_LENGTH(ifWifiTable_oid);

/* ============================================================================
 * COUNTER64 HELPER
 *
 * net-snmp's 'struct counter64' has fields:
 *   u_long high;
 *   u_long low;
 *
 * On aarch64 musl, u_long is 64-bit, so we must mask to 32 bits.
 * ========================================================================== */
static void set_counter64(netsnmp_variable_list *var, uint64_t val)
{
    struct counter64 c64;
    c64.high = (u_long)((val >> 32) & 0xFFFFFFFFUL);
    c64.low  = (u_long)( val        & 0xFFFFFFFFUL);
    snmp_set_var_typed_value(var, ASN_COUNTER64,
                             (unsigned char *)&c64, sizeof(c64));
}

/* ============================================================================
 * HANDLER — called for every GET / GETNEXT / GETBULK
 * ========================================================================== */
static int
ifWifiTable_handler(netsnmp_mib_handler          *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info   *reqinfo,
                    netsnmp_request_info         *requests)
{
    netsnmp_request_info  *request;
    netsnmp_variable_list *var;
    oid    *suffix;
    size_t  suffix_len;
    long    column;
    long    ifIndex;
    ifWifiData *d;
    u_long     gauge_val;    /* for ASN_GAUGE  */
    u_long     counter_val;  /* for ASN_COUNTER */

    (void)handler;   /* suppress unused-parameter warning */
    (void)reginfo;

    for (request = requests; request; request = request->next) {

        if (request->processed) continue;

        var        = request->requestvb;
        suffix     = var->name     + ifWifiTable_oid_len;
        suffix_len = var->name_length - ifWifiTable_oid_len;

        /*
         * OID layout under our table OID:
         *   .1.<column>.<ifIndex>
         *    ^-- entry sub-identifier
         */
        if (suffix_len < 3 || suffix[0] != 1) {
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            continue;
        }

        column  = (long)suffix[1];
        ifIndex = (long)suffix[2];

        d = ifWifi_get_by_ifindex(ifIndex);
        if (!d) {
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
            continue;
        }

        if (reqinfo->mode != MODE_GET) {
            /* All columns are read-only */
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
            continue;
        }

        switch (column) {

        /* ── DisplayString columns ──────────────────────────────────── */
        case COLUMN_IFWIFISSID:
            snmp_set_var_typed_value(var, ASN_OCTET_STR,
                (unsigned char *)d->ssid, strlen(d->ssid));
            break;

        case COLUMN_IFWIFIPAIRWISECIPHER:
            snmp_set_var_typed_value(var, ASN_OCTET_STR,
                (unsigned char *)d->pairwise_cipher,
                strlen(d->pairwise_cipher));
            break;

        case COLUMN_IFWIFIGROUPCIPHER:
            snmp_set_var_typed_value(var, ASN_OCTET_STR,
                (unsigned char *)d->group_cipher,
                strlen(d->group_cipher));
            break;

        /* ── PhysAddress (6-byte MAC) ────────────────────────────────── */
        case COLUMN_IFWIFIBSSID:
            snmp_set_var_typed_value(var, ASN_OCTET_STR,
                d->bssid, 6);
            break;

        /* ── INTEGER columns ─────────────────────────────────────────── */
        case COLUMN_IFWIFICHANNEL:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->channel);
            break;

        case COLUMN_IFWIFICHANNELWIDTH:
            snmp_set_var_typed_integer(var, ASN_INTEGER,
                                       d->channel_width_mhz);
            break;

        case COLUMN_IFWIFIBAND:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->band);
            break;

        case COLUMN_IFWIFISTANDARD:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->standard);
            break;

        case COLUMN_IFWIFISIGNALDBM:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->signal_dbm);
            break;

        case COLUMN_IFWIFINOISEDMB:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->noise_dbm);
            break;

        case COLUMN_IFWIFISNR:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->snr_db);
            break;

        case COLUMN_IFWIFITXMCS:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->tx_mcs);
            break;

        case COLUMN_IFWIFIRXMCS:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->rx_mcs);
            break;

        case COLUMN_IFWIFICONNECTED:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->connected);
            break;

        case COLUMN_IFWIFIAAUTHALG:
            snmp_set_var_typed_integer(var, ASN_INTEGER, d->auth_alg);
            break;

        /* ── Gauge32 columns (bit rates, link quality) ───────────────── */
        case COLUMN_IFWIFITXBITRATE:
            gauge_val = (u_long)d->tx_bitrate_100bps;
            snmp_set_var_typed_value(var, ASN_GAUGE,
                (unsigned char *)&gauge_val, sizeof(gauge_val));
            break;

        case COLUMN_IFWIFIRXBITRATE:
            gauge_val = (u_long)d->rx_bitrate_100bps;
            snmp_set_var_typed_value(var, ASN_GAUGE,
                (unsigned char *)&gauge_val, sizeof(gauge_val));
            break;

        case COLUMN_IFWIFILINKQUALITY:
            gauge_val = (u_long)d->link_quality;
            snmp_set_var_typed_value(var, ASN_GAUGE,
                (unsigned char *)&gauge_val, sizeof(gauge_val));
            break;

        case COLUMN_IFWIFILINKQUALITYMAX:
            gauge_val = (u_long)d->link_quality_max;
            snmp_set_var_typed_value(var, ASN_GAUGE,
                (unsigned char *)&gauge_val, sizeof(gauge_val));
            break;

        /* ── Counter64 columns (tx/rx bytes and packets) ─────────────── */
        case COLUMN_IFWIFITXPACKETS:
            set_counter64(var, d->tx_packets);
            break;

        case COLUMN_IFWIFIRXPACKETS:
            set_counter64(var, d->rx_packets);
            break;

        case COLUMN_IFWIFITXBYTES:
            set_counter64(var, d->tx_bytes);
            break;

        case COLUMN_IFWIFIRXBYTES:
            set_counter64(var, d->rx_bytes);
            break;

        /* ── Counter32 columns (retries, failures, drops) ────────────── */
        case COLUMN_IFWIFITXRETRIES:
            counter_val = (u_long)d->tx_retries;
            snmp_set_var_typed_value(var, ASN_COUNTER,
                (unsigned char *)&counter_val, sizeof(counter_val));
            break;

        case COLUMN_IFWIFITXFAILED:
            counter_val = (u_long)d->tx_failed;
            snmp_set_var_typed_value(var, ASN_COUNTER,
                (unsigned char *)&counter_val, sizeof(counter_val));
            break;

        case COLUMN_IFWIFIRXDROPMISC:
            counter_val = (u_long)d->rx_drop_misc;
            snmp_set_var_typed_value(var, ASN_COUNTER,
                (unsigned char *)&counter_val, sizeof(counter_val));
            break;

        case COLUMN_IFWIFIBEACONLOSS:
            counter_val = (u_long)d->beacon_loss;
            snmp_set_var_typed_value(var, ASN_COUNTER,
                (unsigned char *)&counter_val, sizeof(counter_val));
            break;

        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            break;
        }
    }

    return SNMP_ERR_NOERROR;
}

/* ============================================================================
 * INIT / SHUTDOWN — called by net-snmp agent startup/shutdown
 *
 * Function name MUST match the directory name used in:
 *   ./configure --with-mib-modules="if-mib/ifWifiTable"
 * ========================================================================== */
void init_ifWifiTable(void)
{
    netsnmp_handler_registration *reg;

    DEBUGMSGTL(("ifWifi", "init_ifWifiTable: registering OID subtree\n"));

    reg = netsnmp_create_handler_registration(
              "ifWifiTable",
              ifWifiTable_handler,
              ifWifiTable_oid,
              ifWifiTable_oid_len,
              HANDLER_CAN_RONLY);

    if (!reg) {
        snmp_log(LOG_ERR, "ifWifiTable: failed to create handler registration\n");
        return;
    }

    if (netsnmp_register_handler(reg) != MIB_REGISTERED_OK) {
        snmp_log(LOG_ERR, "ifWifiTable: OID registration failed\n");
        return;
    }

    snmp_log(LOG_INFO,
             "ifWifiTable: registered at .1.3.6.1.4.1.99999.10\n");
}

void shutdown_ifWifiTable(void)
{
    ifWifi_free_data();
}
