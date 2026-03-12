# IFWIFI-MIB Development Guide
# Extending IF-MIB with WiFi Statistics in Net-SNMP V5-9-3
# ============================================================

## 1. Architecture Overview

```
NMS (Zabbix/LibreNMS)
    │  snmpwalk -v2c -c public <device> .1.3.6.1.4.1.99999.10
    ▼
snmpd (net-snmp 5.9.3)
    │
    ├── IF-MIB::ifTable        (existing, agents/mibgroup/if-mib/ifTable/*)
    │       ifIndex, ifDescr, ifType, ifSpeed, ifOperStatus ...
    │
    └── IFWIFI-MIB::ifWifiTable  ◄─── YOUR NEW MODULE
            AUGMENTS ifEntry (same ifIndex)
            ifWifiSSID, ifWifiSignalDBm, ifWifiTxBitRate ...

Your module reads from Linux kernel:
    /proc/net/wireless       ← signal, noise, link quality
    iw dev <iface> link      ← SSID, bitrate, MCS, channel
    iw dev <iface> station dump ← packet/byte counters, retries
```

---

## 2. File Layout in Net-SNMP Source Tree

```
net-snmp-5.9.3/
├── mibs/
│   └── IFWIFI-MIB.txt                    ← SMIv2 MIB definition
│
└── agent/
    └── mibgroup/
        └── if-mib/
            └── ifWifiTable/
                ├── ifWifiTable.h          ← data structures, column defines
                ├── ifWifiTable.c          ← SNMP handler, OID registration
                └── ifWifiTable_data_access.c  ← reads iw / /proc
```

Compare this to the existing ifTable structure:
```
agent/mibgroup/if-mib/ifTable/
    ifTable.h
    ifTable.c
    ifTable_data_access.c
    ifTable_interface.c    ← (optional, for full table iterator helper)
```

---

## 3. The Three Source Files Explained

### 3.1 ifWifiTable.h — Data Contract

This header defines:
- Column number constants (`COLUMN_IFWIFISSID = 1` etc.)
- Enumeration values for INTEGER columns (band, standard, auth)
- The `ifWifiData` struct — one instance per wireless interface
- Public API: `ifWifi_load_data()`, `ifWifi_get_by_ifindex()`, `ifWifi_free_data()`

**Key design decision:** `ifIndex` is the row key (matches parent ifTable).
This is what `AUGMENTS { ifEntry }` means in the MIB — same index space.

### 3.2 ifWifiTable_data_access.c — Linux Data Collection

Three independent data sources, read in this order:

```
/proc/net/wireless
│  Format: "  wlan0: 0000  55.  -56.  -95.  ..."
│  Gives:  link_quality, signal_dbm, noise_dbm
│
iw dev <iface> link
│  Gives:  connected, SSID, BSSID, freq→channel→band,
│           tx_bitrate, rx_bitrate, tx_mcs, rx_mcs, standard
│
iw dev <iface> station dump
   Gives:  tx_packets, rx_packets, tx_bytes, rx_bytes,
            tx_retries, tx_failed, rx_drop_misc, beacon_loss
```

**Caching:** Data is cached for `IFWIFI_CACHE_TIMEOUT` (15) seconds.
Every SNMP GET does NOT call `iw` — only one call per 15s. This prevents
the agent from overwhelming the kernel with netlink requests.

### 3.3 ifWifiTable.c — SNMP Handler

The handler follows the standard net-snmp pattern:

```c
/* 1. Register at startup */
void init_ifWifiTable(void) {
    netsnmp_register_handler(
        netsnmp_create_handler_registration(
            "ifWifiTable",
            ifWifiTable_handler,   /* your callback */
            ifWifiTable_oid,
            ifWifiTable_oid_len,
            HANDLER_CAN_RONLY
        )
    );
}

/* 2. Handle GET requests */
static int ifWifiTable_handler(...) {
    /* Extract column + ifIndex from OID suffix */
    column  = suffix[1];
    ifIndex = suffix[2];

    /* Look up cached data */
    d = ifWifi_get_by_ifindex(ifIndex);

    /* Return the right value for the column */
    switch (column) {
    case COLUMN_IFWIFISSID:
        snmp_set_var_typed_value(var, ASN_OCTET_STR, d->ssid, ...);
        break;
    ...
    }
}
```

---

## 4. OID Assignment

```
enterprises (1.3.6.1.4.1)
    └── 99999  ← YOUR IANA PEN (replace this!)
          └── 10  ← wifi subtree
                └── 1  ← ifWifiObjects
                      └── 1  ← ifWifiTable
                            └── 1  ← ifWifiEntry
                                  └── <column>
                                          └── <ifIndex>

Example full OID for signal of wlan0 (ifIndex=3):
  .1.3.6.1.4.1.99999.10.1.1.1.7.3
                             ^ ^
                       column=7 ifIndex=3
```

**IMPORTANT:** Get a real IANA Private Enterprise Number (PEN) for production:
https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
It is free and permanent.

---

## 5. Build Methods

### Method A — In-tree (recommended for production)

```bash
# 1. Copy module into net-snmp source
cp -r if-mib/ifWifiTable  net-snmp-5.9.3/agent/mibgroup/if-mib/

# 2. Copy MIB file
cp mib/IFWIFI-MIB.txt  net-snmp-5.9.3/mibs/

# 3. Configure (key flag: --with-mib-modules)
cd net-snmp-5.9.3
./configure \
    --with-mib-modules="if-mib/ifWifiTable" \
    --prefix=/usr \
    --sysconfdir=/etc \
    --with-default-snmp-version=2 \
    --enable-ipv6

# 4. Build and install
make -j$(nproc)
sudo make install

# 5. Verify the module was compiled in
strings /usr/sbin/snmpd | grep ifWifi
# Should print: ifWifiTable
```

### Method B — dlmod shared library (no recompile)

```bash
# Build .so
gcc -shared -fPIC -o ifWifiTable.so \
    ifWifiTable.c ifWifiTable_data_access.c \
    $(net-snmp-config --base-cflags) \
    $(net-snmp-config --agent-libs)

# Deploy
sudo install -m755 ifWifiTable.so /usr/lib/snmp/

# Add to snmpd.conf
echo "dlmod ifWifiTable /usr/lib/snmp/ifWifiTable.so" \
    >> /etc/snmp/snmpd.conf

sudo systemctl restart snmpd
```

---

## 6. snmpd.conf Configuration

Add these lines to `/etc/snmp/snmpd.conf`:

```
# ── WiFi MIB — load the module (dlmod approach only) ──
dlmod ifWifiTable /usr/lib/snmp/ifWifiTable.so

# ── Access control — allow NMS to read WiFi OID tree ──
view   systemview  included  .1.3.6.1.4.1.99999
rocommunity public  default  .1.3.6.1.4.1.99999

# ── Optional: SNMPv3 user with access ──
# rouser wifimon auth .1.3.6.1.4.1.99999

# ── agentx for sub-agent approach ──
# master agentx
# agentXSocket /var/run/agentx.sock
```

---

## 7. Testing Step by Step

```bash
# Step 1: Verify MIB loads
snmptranslate -m +IFWIFI-MIB -IR ifWifiSSID
# Expected: IFWIFI-MIB::ifWifiSSID

# Step 2: Find your WiFi interface's ifIndex
ip link show | grep -E '^[0-9]+:.*wlan'
# e.g.: "3: wlan0: <BROADCAST,MULTICAST,UP>"  → ifIndex=3

# Step 3: Walk the full WiFi table
snmpwalk -v2c -c public localhost .1.3.6.1.4.1.99999.10

# Step 4: GET specific values
snmpget -v2c -c public localhost \
    .1.3.6.1.4.1.99999.10.1.1.1.7.3   # signal dBm for ifIndex=3

# Step 5: Use MIB names (with -m flag)
snmpget -v2c -c public \
    -m +IFWIFI-MIB \
    -M +/usr/share/snmp/mibs \
    localhost IFWIFI-MIB::ifWifiSSID.3

# Step 6: Run the full test script
bash tools/test_wifi_mib.sh localhost public
```

---

## 8. AUGMENTS vs New Table — When to Use Which

| Approach | When to use |
|---|---|
| `AUGMENTS ifEntry` | You want one-to-one mapping — exactly one WiFi row per ifTable row. Index is inherited. |
| New table with `ifIndex` as index | You want to allow multiple rows per interface (e.g., AP mode with multiple clients). More flexible. |
| `AUGMENTS ifXEntry` | Extending the extended table. Use if your objects logically belong with ifXTable columns. |

This module uses `AUGMENTS ifEntry` which is the right choice for a
station (client) interface — exactly one association per interface.
For AP mode with multiple client stations, use a standalone table
indexed by `{ ifIndex, stationMacAddress }`.

---

## 9. Adding a New Column (Step-by-Step)

Example: Add `ifWifiBeaconInterval` (beacon interval in TU = 1024 µs).

**Step 1 — Add to MIB file (IFWIFI-MIB.txt):**
```
ifWifiBeaconInterval OBJECT-TYPE
    SYNTAX      Integer32 (0..65535)
    UNITS       "Time Units (1024 microseconds)"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Beacon interval in 802.11 Time Units."
    ::= { ifWifiEntry 28 }
```
Add to `IfWifiEntry ::= SEQUENCE { ... ifWifiBeaconInterval Integer32 }`.

**Step 2 — Add to data struct (ifWifiTable.h):**
```c
#define COLUMN_IFWIFIBEACONINTERVAL    28
/* In ifWifiData struct: */
int beacon_interval_tu;
```

**Step 3 — Collect data (ifWifiTable_data_access.c):**
```c
/* In read_iw_link(): */
else if (strncmp(s, "beacon int:", 11) == 0) {
    sscanf(s + 11, "%d", &d->beacon_interval_tu);
}
```

**Step 4 — Serve via SNMP (ifWifiTable.c):**
```c
case COLUMN_IFWIFIBEACONINTERVAL:
    snmp_set_var_typed_integer(var, ASN_INTEGER,
                               d->beacon_interval_tu);
    break;
```

That is the complete cycle. Four touches across four places.

---

## 10. Integration with Your NXP-JD / HeartOfGold OpenWrt Device

Since your device already runs the AgentX sub-agent (`nxpjd_subagent.py`),
you can add WiFi statistics there too — no C compilation needed on the device:

```python
# In mib_80211.py — already exists on your device
# Add these new OIDs to the existing 802.11 registration:

WIFI_SIGNAL_OID    = (1, 3, 6, 1, 4, 1, 99999, 10, 1, 1, 1, 7)
WIFI_TX_BITRATE    = (1, 3, 6, 1, 4, 1, 99999, 10, 1, 1, 1, 12)
WIFI_TX_RETRIES    = (1, 3, 6, 1, 4, 1, 99999, 10, 1, 1, 1, 20)
```

The C module in this guide is for a Linux server running full net-snmp.
For OpenWrt with the Python AgentX agent, use the same OID tree but
register via the AgentX protocol (already done in `nxpjd_subagent.py`).
