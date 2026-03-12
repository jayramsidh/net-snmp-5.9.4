/*
 * ifWifiTable.c
 *
 * SNMP agent handler for IFWIFI-MIB::ifWifiTable
 * Net-SNMP 5.9.4 / OpenWrt 24.10 compatible
 *
 * Supports:
 *   - GET
 *   - GETNEXT
 *   - GETBULK (through GETNEXT path)
 *
 * OID structure:
 *   enterprises.99999.10.1.1.1.<column>.<ifIndex>
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <string.h>

#include "ifWifiTable.h"

/* enterprises.99999.10.1.1 */
static oid    ifWifiTable_oid[]   = { 1,3,6,1,4,1,99999,10,1,1 };
static size_t ifWifiTable_oid_len = OID_LENGTH(ifWifiTable_oid);

/*
 * Maximum ifIndex to scan while resolving GETNEXT.
 * This is pragmatic and works well on embedded/OpenWrt systems.
 */
#define IFWIFI_MAX_IFINDEX_SCAN 4096

static const long ifWifi_columns[] = {
    COLUMN_IFWIFISSID,
    COLUMN_IFWIFIBSSID,
    COLUMN_IFWIFICHANNEL,
    COLUMN_IFWIFICHANNELWIDTH,
    COLUMN_IFWIFIBAND,
    COLUMN_IFWIFISTANDARD,
    COLUMN_IFWIFISIGNALDBM,
    COLUMN_IFWIFINOISEDMB,
    COLUMN_IFWIFISNR,
    COLUMN_IFWIFILINKQUALITY,
    COLUMN_IFWIFILINKQUALITYMAX,
    COLUMN_IFWIFITXBITRATE,
    COLUMN_IFWIFIRXBITRATE,
    COLUMN_IFWIFITXMCS,
    COLUMN_IFWIFIRXMCS,
    COLUMN_IFWIFITXPACKETS,
    COLUMN_IFWIFIRXPACKETS,
    COLUMN_IFWIFITXBYTES,
    COLUMN_IFWIFIRXBYTES,
    COLUMN_IFWIFITXRETRIES,
    COLUMN_IFWIFITXFAILED,
    COLUMN_IFWIFIRXDROPMISC,
    COLUMN_IFWIFIBEACONLOSS,
    COLUMN_IFWIFICONNECTED,
    COLUMN_IFWIFIAUTHALG,
    COLUMN_IFWIFIPAIRWISECIPHER,
    COLUMN_IFWIFIGROUPCIPHER
};

#define IFWIFI_NUM_COLUMNS (sizeof(ifWifi_columns) / sizeof(ifWifi_columns[0]))

/* -------------------------------------------------------------------------- */
/* Counter64 helper                                                            */
/* -------------------------------------------------------------------------- */
static void
set_counter64(netsnmp_variable_list *var, uint64_t val)
{
    struct counter64 c64;
    c64.high = (u_long)((val >> 32) & 0xFFFFFFFFUL);
    c64.low  = (u_long)(val & 0xFFFFFFFFUL);

    snmp_set_var_typed_value(var, ASN_COUNTER64,
                             (const u_char *)&c64, sizeof(c64));
}

/* -------------------------------------------------------------------------- */
/* Fill one instance value                                                     */
/* -------------------------------------------------------------------------- */
static int
ifWifi_fill_value(netsnmp_variable_list *var, long column, const ifWifiData *d)
{
    uint32_t u32;

    switch (column) {
    case COLUMN_IFWIFISSID:
        snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                 (const u_char *)d->ssid, strlen(d->ssid));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIPAIRWISECIPHER:
        snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                 (const u_char *)d->pairwise_cipher,
                                 strlen(d->pairwise_cipher));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIGROUPCIPHER:
        snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                 (const u_char *)d->group_cipher,
                                 strlen(d->group_cipher));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIBSSID:
        snmp_set_var_typed_value(var, ASN_OCTET_STR, d->bssid, 6);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFICHANNEL:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->channel);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFICHANNELWIDTH:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->channel_width_mhz);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIBAND:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->band);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFISTANDARD:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->standard);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFISIGNALDBM:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->signal_dbm);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFINOISEDMB:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->noise_dbm);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFISNR:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->snr_db);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXMCS:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->tx_mcs);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXMCS:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->rx_mcs);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFICONNECTED:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->connected);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIAUTHALG:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->auth_alg);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXBITRATE:
        u32 = d->tx_bitrate_100bps;
        snmp_set_var_typed_value(var, ASN_GAUGE,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXBITRATE:
        u32 = d->rx_bitrate_100bps;
        snmp_set_var_typed_value(var, ASN_GAUGE,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFILINKQUALITY:
        u32 = d->link_quality;
        snmp_set_var_typed_value(var, ASN_GAUGE,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFILINKQUALITYMAX:
        u32 = d->link_quality_max;
        snmp_set_var_typed_value(var, ASN_GAUGE,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXPACKETS:
        set_counter64(var, d->tx_packets);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXPACKETS:
        set_counter64(var, d->rx_packets);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXBYTES:
        set_counter64(var, d->tx_bytes);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXBYTES:
        set_counter64(var, d->rx_bytes);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXRETRIES:
        u32 = d->tx_retries;
        snmp_set_var_typed_value(var, ASN_COUNTER,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFITXFAILED:
        u32 = d->tx_failed;
        snmp_set_var_typed_value(var, ASN_COUNTER,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXDROPMISC:
        u32 = d->rx_drop_misc;
        snmp_set_var_typed_value(var, ASN_COUNTER,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIBEACONLOSS:
        u32 = d->beacon_loss;
        snmp_set_var_typed_value(var, ASN_COUNTER,
                                 (const u_char *)&u32, sizeof(u32));
        return SNMP_ERR_NOERROR;

    default:
        return SNMP_NOSUCHOBJECT;
    }
}

/* -------------------------------------------------------------------------- */
/* Resolve exact request                                                       */
/* -------------------------------------------------------------------------- */
static int
ifWifi_resolve_exact(const oid *name, size_t name_len, long *column, long *ifIndex)
{
    const oid *suffix;
    size_t suffix_len;

    if (name_len < ifWifiTable_oid_len)
        return 0;

    if (snmp_oid_compare(name, ifWifiTable_oid_len,
                         ifWifiTable_oid, ifWifiTable_oid_len) != 0)
        return 0;

    suffix = name + ifWifiTable_oid_len;
    suffix_len = name_len - ifWifiTable_oid_len;

    /* Expect .1.<column>.<ifIndex> */
    if (suffix_len != 3 || suffix[0] != 1)
        return 0;

    *column  = (long)suffix[1];
    *ifIndex = (long)suffix[2];
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Find next valid instance for GETNEXT / GETBULK                              */
/* -------------------------------------------------------------------------- */
static int
ifWifi_find_next(const oid *req_oid, size_t req_oid_len,
                 oid *best_oid, size_t *best_oid_len,
                 long *best_col, long *best_ifindex, ifWifiData **best_data)
{
    size_t i;
    int found = 0;

    for (i = 0; i < IFWIFI_NUM_COLUMNS; i++) {
        long col = ifWifi_columns[i];
        long idx;

        for (idx = 1; idx <= IFWIFI_MAX_IFINDEX_SCAN; idx++) {
            ifWifiData *d;
            oid cand[128];
            size_t cand_len = 0;

            d = ifWifi_get_by_ifindex(idx);
            if (!d)
                continue;

            memcpy(cand, ifWifiTable_oid, ifWifiTable_oid_len * sizeof(oid));
            cand_len = ifWifiTable_oid_len;
            cand[cand_len++] = 1;        /* ifWifiEntry */
            cand[cand_len++] = (oid)col; /* column */
            cand[cand_len++] = (oid)idx; /* ifIndex */

            if (snmp_oid_compare(cand, cand_len, req_oid, req_oid_len) <= 0)
                continue;

            if (!found ||
                snmp_oid_compare(cand, cand_len, best_oid, *best_oid_len) < 0) {
                memcpy(best_oid, cand, cand_len * sizeof(oid));
                *best_oid_len = cand_len;
                *best_col = col;
                *best_ifindex = idx;
                *best_data = d;
                found = 1;
            }
        }
    }

    return found;
}

/* -------------------------------------------------------------------------- */
/* Main handler                                                                */
/* -------------------------------------------------------------------------- */
static int
ifWifiTable_handler(netsnmp_mib_handler          *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info   *reqinfo,
                    netsnmp_request_info         *requests)
{
    netsnmp_request_info *request;

    (void)handler;
    (void)reginfo;

    for (request = requests; request; request = request->next) {
        netsnmp_variable_list *var = request->requestvb;

        if (request->processed)
            continue;

        switch (reqinfo->mode) {

        case MODE_GET: {
            long column, ifIndex;
            ifWifiData *d;

            if (!ifWifi_resolve_exact(var->name, var->name_length,
                                      &column, &ifIndex)) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                continue;
            }

            d = ifWifi_get_by_ifindex(ifIndex);
            if (!d) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }

            if (ifWifi_fill_value(var, column, d) != SNMP_ERR_NOERROR) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            }
            break;
        }

        case MODE_GETNEXT:
        case MODE_GETBULK: {
            oid next_oid[128];
            size_t next_oid_len = 0;
            long next_col = 0, next_ifindex = 0;
            ifWifiData *next_data = NULL;

            if (!ifWifi_find_next(var->name, var->name_length,
                                  next_oid, &next_oid_len,
                                  &next_col, &next_ifindex, &next_data)) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                continue;
            }

            snmp_set_var_objid(var, next_oid, next_oid_len);

            if (ifWifi_fill_value(var, next_col, next_data) != SNMP_ERR_NOERROR) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            }
            break;
        }

        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
            break;
        }
    }

    return SNMP_ERR_NOERROR;
}

/* -------------------------------------------------------------------------- */
/* Init / shutdown                                                             */
/* -------------------------------------------------------------------------- */
void
init_ifWifiTable(void)
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

    snmp_log(LOG_INFO, "ifWifiTable: registered at .1.3.6.1.4.1.99999.10\n");
}

void
shutdown_ifWifiTable(void)
{
    ifWifi_free_data();
}
