# MikroTik Router — Remediation Guide

## Accessing the admin panel

MikroTik can be managed via Winbox, WebFig, or SSH.

**Winbox (recommended):**
1. Download Winbox from `mikrotik.com/download`
2. Open Winbox and click **Neighbors** to discover your router
3. Click on the MAC address and click **Connect**
4. Default credentials: `admin` / *(no password)* — **set a password immediately**

**WebFig:**
1. Open a browser and go to `http://192.168.88.1`
2. Log in with admin credentials

**SSH:**
```
ssh admin@192.168.88.1
```

---

## Disable UPnP

**Via Winbox:**
1. Go to **IP** → **UPnP**
2. Click **Settings**
3. Uncheck **Enabled**
4. Click **OK**

**Via SSH/Terminal:**
```
/ip upnp set enabled=no
```

---

## Review and remove port forwarding rules

**Via Winbox:**
1. Go to **IP** → **Firewall** → **NAT**
2. Review all rules with `action=dst-nat`
3. Select any rules you did not create and press **Delete**

**Via SSH/Terminal:**
```
/ip firewall nat print
/ip firewall nat remove numbers=X
```
Replace `X` with the rule number to remove.

---

## Review connection tracking

```
/ip firewall connection print
```
Look for unexpected external connections to internal devices.

---

## Disable remote Winbox access from WAN

**Via SSH/Terminal:**
```
/ip firewall filter add chain=input action=drop \
  in-interface=ether1 protocol=tcp dst-port=8291 \
  comment="Block Winbox from WAN"
```

---

## Disable Telnet

```
/ip service set telnet disabled=yes
```

## Disable unused services

```
/ip service print
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
```

---

## Update firmware

**Via Winbox:**
1. Go to **System** → **Packages**
2. Click **Check For Updates**
3. Select **stable** channel and click **Download & Install**

**Via SSH/Terminal:**
```
/system package update check-for-updates
/system package update install
```

---

## Verify the fix

After making changes run Muhafiz again.
The correlation should no longer appear if the port has been closed successfully.