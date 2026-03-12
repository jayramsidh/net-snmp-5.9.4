/*
 * ifWifiTable.c
 *
 * SNMP agent handler for IFWIFI-MIB::ifWifiTable
 * Net-SNMP 5.9.4 / OpenWrt 24.10 compatible
 *
 * Uses Net-SNMP table iterator helper so:
 *   - snmpget works
 *   - snmpwalk on IFWIFI subtree works
 *   - global snmpwalk .1 can discover the subtree correctly
 *
 * OID structure:
 *   enterprises.99999.10.1.1.1.<column>.<ifIndex>
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <string.h>
#include <stdlib.h>

#include "ifWifiTable.h"

/* enterprises.99999.10.1.1 */
static oid ifWifiTable_oid[] = { 1,3,6,1,4,1,99999,10,1,1 };

static netsnmp_table_registration_info *ifWifiTable_info = NULL;
static netsnmp_iterator_info           *ifWifiTable_iinfo = NULL;

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
/* Return one column value                                                     */
/* -------------------------------------------------------------------------- */
static int
ifWifi_set_var(netsnmp_variable_list *var, long column, const ifWifiData *d)
{
    uint32_t u32;

    switch (column) {
    case COLUMN_IFWIFISSID:
        snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                 (const u_char *)d->ssid, strlen(d->ssid));
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

    case COLUMN_IFWIFITXMCS:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->tx_mcs);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIRXMCS:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->rx_mcs);
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

    case COLUMN_IFWIFICONNECTED:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->connected);
        return SNMP_ERR_NOERROR;

    case COLUMN_IFWIFIAUTHALG:
        snmp_set_var_typed_integer(var, ASN_INTEGER, d->auth_alg);
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

    default:
        return SNMP_NOSUCHOBJECT;
    }
}

/* -------------------------------------------------------------------------- */
/* Iterator context                                                            */
/* -------------------------------------------------------------------------- */

typedef struct ifWifiIterContext_s {
    long current_ifindex;
} ifWifiIterContext;

/* Return first valid row */
static netsnmp_variable_list *
ifWifiTable_get_first_data_point(void **loop_context,
                                 void **data_context,
                                 netsnmp_variable_list *index_data,
                                 netsnmp_iterator_info *data)
{
    long idx;
    ifWifiData *d;
    ifWifiIterContext *ctx;

    (void)data;

    ifWifi_load_data();

    ctx = SNMP_MALLOC_TYPEDEF(ifWifiIterContext);
    if (!ctx)
        return NULL;

    for (idx = 1; idx <= 4096; idx++) {
        d = ifWifi_get_by_ifindex(idx);
        if (d) {
            ctx->current_ifindex = idx;
            *loop_context = ctx;
            *data_context = d;
            snmp_set_var_typed_integer(index_data, ASN_INTEGER, idx);
            return index_data;
        }
    }

    free(ctx);
    return NULL;
}

/* Return next valid row */
static netsnmp_variable_list *
ifWifiTable_get_next_data_point(void **loop_context,
                                void **data_context,
                                netsnmp_variable_list *index_data,
                                netsnmp_iterator_info *data)
{
    ifWifiIterContext *ctx = (ifWifiIterContext *)(*loop_context);
    long idx;
    ifWifiData *d;

    (void)data;

    if (!ctx)
        return NULL;

    for (idx = ctx->current_ifindex + 1; idx <= 4096; idx++) {
        d = ifWifi_get_by_ifindex(idx);
        if (d) {
            ctx->current_ifindex = idx;
            *data_context = d;
            snmp_set_var_typed_integer(index_data, ASN_INTEGER, idx);
            return index_data;
        }
    }

    free(ctx);
    *loop_context = NULL;
    *data_context = NULL;
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Main table handler                                                          */
/* -------------------------------------------------------------------------- */
static int
ifWifiTable_handler(netsnmp_mib_handler          *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info   *reqinfo,
                    netsnmp_request_info         *requests)
{
    netsnmp_request_info       *request;
    netsnmp_table_request_info *table_info;

    (void)handler;
    (void)reginfo;

    switch (reqinfo->mode) {
    case MODE_GET:
        for (request = requests; request; request = request->next) {
            ifWifiData *d = (ifWifiData *)netsnmp_extract_iterator_context(request);
            table_info = netsnmp_extract_table_info(request);

            if (!d || !table_info) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }

            if (ifWifi_set_var(request->requestvb, table_info->colnum, d)
                != SNMP_ERR_NOERROR) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            }
        }
        break;

    default:
        for (request = requests; request; request = request->next) {
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
        }
        break;
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

    DEBUGMSGTL(("ifWifi", "init_ifWifiTable: registering iterator table\n"));

    reg = netsnmp_create_handler_registration(
        "ifWifiTable",
        ifWifiTable_handler,
        ifWifiTable_oid,
        OID_LENGTH(ifWifiTable_oid),
        HANDLER_CAN_RONLY
    );

    if (!reg) {
        snmp_log(LOG_ERR, "ifWifiTable: failed to create handler registration\n");
        return;
    }

    ifWifiTable_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    ifWifiTable_iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    if (!ifWifiTable_info || !ifWifiTable_iinfo) {
        snmp_log(LOG_ERR, "ifWifiTable: memory allocation failed\n");
        return;
    }

    netsnmp_table_helper_add_indexes(ifWifiTable_info, ASN_INTEGER, 0);
    ifWifiTable_info->min_column = COLUMN_IFWIFISSID;
    ifWifiTable_info->max_column = COLUMN_IFWIFIGROUPCIPHER;

    ifWifiTable_iinfo->get_first_data_point = ifWifiTable_get_first_data_point;
    ifWifiTable_iinfo->get_next_data_point  = ifWifiTable_get_next_data_point;
    ifWifiTable_iinfo->table_reginfo        = ifWifiTable_info;

    if (netsnmp_register_table_iterator(reg, ifWifiTable_iinfo) != MIB_REGISTERED_OK) {
        snmp_log(LOG_ERR, "ifWifiTable: iterator registration failed\n");
        return;
    }

    snmp_log(LOG_INFO, "ifWifiTable: registered at .1.3.6.1.4.1.99999.10\n");
}

void
shutdown_ifWifiTable(void)
{
    ifWifi_free_data();
}
