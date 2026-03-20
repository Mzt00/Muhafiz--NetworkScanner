# TP-Link Router — Remediation Guide

## Accessing the admin panel

1. Open a browser and go to `http://192.168.0.1` or `http://tplinkwifi.net`
2. Log in with your admin credentials
3. Default credentials (if never changed): `admin` / `admin` — **change these immediately**

---

## Disable UPnP

**Via web UI (Archer series):**
1. Go to **Advanced** → **NAT Forwarding** → **UPnP**
2. Toggle UPnP to **Off**
3. Click **Save**

**Via Tether app:**
1. Open the TP-Link Tether app
2. Tap your router → **Advanced** → **UPnP**
3. Toggle off and save

---

## Review and remove port forwarding rules

1. Go to **Advanced** → **NAT Forwarding** → **Virtual Servers**
2. Review all listed rules
3. Select any rules you did not create and click **Delete**
4. Click **Save**

---

## Disable remote management

1. Go to **Advanced** → **System** → **Administration**
2. Under **Remote Management** set to **Disabled**
3. Click **Save**

---

## Update firmware

1. Go to **Advanced** → **System** → **Firmware Upgrade**
2. Click **Check for Upgrades**
3. If available click **Upgrade Now**

---

## Disable DDNS (if not needed)

1. Go to **Advanced** → **Network** → **Dynamic DNS**
2. If you are not using DDNS set it to **Disable**
3. Click **Save**

---

## Verify the fix

After making changes run Muhafiz again.
The correlation should no longer appear if the port has been closed successfully.