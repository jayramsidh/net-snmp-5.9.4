/*
 * ifWifiTable.c
 *
 * Net-SNMP agent handler for IFWIFI-MIB::ifWifiTable
 * Net-SNMP V5-9-3-branch compatible
 *
 * Architecture (mirrors if-mib/ifTable pattern from V5-9-3):
 *
 *   init_ifWifiTable()
 *       └─ netsnmp_register_handler()
 *              └─ ifWifiTable_handler()  ← called on every GET/GETNEXT
 *                      └─ ifWifi_get_by_ifindex()  ← data_access layer
 *
 * OID tree:
 *   enterprises.99999.10.1.1.1  = ifWifiEntry
 *   enterprises.99999.10.1.1.1.<column>.<ifIndex>
 *
 * To test:
 *   snmpget  -v2c -c public localhost enterprises.99999.10.1.1.1.7.3
 *   snmpwalk -v2c -c public localhost enterprises.99999.10.1.1.1
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <string.h>
#include "ifWifiTable.h"

/* ── OID for ifWifiTable (enterprises.99999.10.1.1) ───────────────────── */
/*    Replace 99999 with your real IANA PEN                                */
static oid ifWifiTable_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 10, 1, 1 };
static size_t ifWifiTable_oid_len = OID_LENGTH(ifWifiTable_oid);

/* ============================================================================
 * HANDLER — called by net-snmp for every GET / GETNEXT / GETBULK
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

    for (request = requests; request; request = request->next) {
        var = request->requestvb;

        if (request->processed) continue;

        /*
         * OID structure under ifWifiEntry:
         *   <table_oid>.1.<column>.<ifIndex>
         *              ^entry subid
         */
        suffix     = var->name + ifWifiTable_oid_len;
        suffix_len = var->name_length - ifWifiTable_oid_len;

        /* Need at least: entry(1) + column + ifIndex */
        if (suffix_len < 3 || suffix[0] != 1) {
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            continue;
        }

        column  = (long)suffix[1];
        ifIndex = (long)suffix[2];

        /* Fetch data (from cache or refresh) */
        d = ifWifi_get_by_ifindex(ifIndex);
        if (!d) {
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
            continue;
        }

        /* ── Dispatch to the right column ─────────────────────────────── */
        switch (reqinfo->mode) {
        case MODE_GET:
            switch (column) {

            case COLUMN_IFWIFISSID:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                    (unsigned char *)d->ssid, strlen(d->ssid));
                break;

            case COLUMN_IFWIFIBSSID:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                    d->bssid, 6);
                break;

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

            case COLUMN_IFWIFILINKQUALITY:
                snmp_set_var_typed_value(var, ASN_GAUGE,
                    (unsigned char *)&d->link_quality,
                    sizeof(d->link_quality));
                break;

            case COLUMN_IFWIFILINKQUALITYMAX:
                snmp_set_var_typed_value(var, ASN_GAUGE,
                    (unsigned char *)&d->link_quality_max,
                    sizeof(d->link_quality_max));
                break;

            case COLUMN_IFWIFITXBITRATE:
                snmp_set_var_typed_value(var, ASN_GAUGE,
                    (unsigned char *)&d->tx_bitrate_100bps,
                    sizeof(d->tx_bitrate_100bps));
                break;

            case COLUMN_IFWIFIRXBITRATE:
                snmp_set_var_typed_value(var, ASN_GAUGE,
                    (unsigned char *)&d->rx_bitrate_100bps,
                    sizeof(d->rx_bitrate_100bps));
                break;

            case COLUMN_IFWIFITXMCS:
                snmp_set_var_typed_integer(var, ASN_INTEGER, d->tx_mcs);
                break;

            case COLUMN_IFWIFIRXMCS:
                snmp_set_var_typed_integer(var, ASN_INTEGER, d->rx_mcs);
                break;

            case COLUMN_IFWIFITXPACKETS: {
                struct counter64 c64;
                c64.high = (unsigned long)(d->tx_packets >> 32);
                c64.low  = (unsigned long)(d->tx_packets & 0xFFFFFFFF);
                snmp_set_var_typed_value(var, ASN_COUNTER64,
                    (unsigned char *)&c64, sizeof(c64));
                break;
            }

            case COLUMN_IFWIFIRXPACKETS: {
                struct counter64 c64;
                c64.high = (unsigned long)(d->rx_packets >> 32);
                c64.low  = (unsigned long)(d->rx_packets & 0xFFFFFFFF);
                snmp_set_var_typed_value(var, ASN_COUNTER64,
                    (unsigned char *)&c64, sizeof(c64));
                break;
            }

            case COLUMN_IFWIFITXBYTES: {
                struct counter64 c64;
                c64.high = (unsigned long)(d->tx_bytes >> 32);
                c64.low  = (unsigned long)(d->tx_bytes & 0xFFFFFFFF);
                snmp_set_var_typed_value(var, ASN_COUNTER64,
                    (unsigned char *)&c64, sizeof(c64));
                break;
            }

            case COLUMN_IFWIFIRXBYTES: {
                struct counter64 c64;
                c64.high = (unsigned long)(d->rx_bytes >> 32);
                c64.low  = (unsigned long)(d->rx_bytes & 0xFFFFFFFF);
                snmp_set_var_typed_value(var, ASN_COUNTER64,
                    (unsigned char *)&c64, sizeof(c64));
                break;
            }

            case COLUMN_IFWIFITXRETRIES:
                snmp_set_var_typed_value(var, ASN_COUNTER,
                    (unsigned char *)&d->tx_retries,
                    sizeof(d->tx_retries));
                break;

            case COLUMN_IFWIFITXFAILED:
                snmp_set_var_typed_value(var, ASN_COUNTER,
                    (unsigned char *)&d->tx_failed,
                    sizeof(d->tx_failed));
                break;

            case COLUMN_IFWIFIRXDROPMISC:
                snmp_set_var_typed_value(var, ASN_COUNTER,
                    (unsigned char *)&d->rx_drop_misc,
                    sizeof(d->rx_drop_misc));
                break;

            case COLUMN_IFWIFIBEACONLOSS:
                snmp_set_var_typed_value(var, ASN_COUNTER,
                    (unsigned char *)&d->beacon_loss,
                    sizeof(d->beacon_loss));
                break;

            case COLUMN_IFWIFICONNECTED:
                snmp_set_var_typed_integer(var, ASN_INTEGER, d->connected);
                break;

            case COLUMN_IFWIFIAAUTHALG:
                snmp_set_var_typed_integer(var, ASN_INTEGER, d->auth_alg);
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

            default:
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                break;
            }
            break;   /* MODE_GET */

        default:
            /* This MIB is read-only; no SET support */
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
            break;
        }
    }

    return SNMP_ERR_NOERROR;
}

/* ============================================================================
 * REGISTRATION
 * ========================================================================== */

/*
 * init_ifWifiTable()
 *
 * Called during agent startup. This function name must match the
 * --with-mib-modules= name given to configure, e.g.:
 *   ./configure --with-mib-modules="if-mib/ifWifiTable"
 *
 * Registers the OID subtree with an instance handler (scalar-style).
 * For a full table iterator, use netsnmp_create_handler_registration()
 * with HANDLER_CAN_RONLY + table iterator helpers — shown in the
 * "Advanced" section of the dev guide.
 */
void init_ifWifiTable(void)
{
    netsnmp_handler_registration *reg;

    DEBUGMSGTL(("ifWifi", "Initializing ifWifiTable\n"));

    reg = netsnmp_create_handler_registration(
              "ifWifiTable",          /* handler name (for debug) */
              ifWifiTable_handler,    /* callback function */
              ifWifiTable_oid,        /* base OID */
              ifWifiTable_oid_len,    /* OID length */
              HANDLER_CAN_RONLY);     /* read-only */

    if (!reg) {
        snmp_log(LOG_ERR, "ifWifiTable: failed to create handler\n");
        return;
    }

    if (netsnmp_register_handler(reg) != MIB_REGISTERED_OK) {
        snmp_log(LOG_ERR, "ifWifiTable: failed to register OID\n");
        return;
    }

    snmp_log(LOG_INFO, "ifWifiTable: registered at enterprises.99999.10\n");
}

void shutdown_ifWifiTable(void)
{
    ifWifi_free_data();
}
