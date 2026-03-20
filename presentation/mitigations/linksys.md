# Linksys Router — Remediation Guide

## Accessing the admin panel

1. Open a browser and go to `http://192.168.1.1`
2. Log in with your admin credentials
3. Default credentials: `admin` / `admin` — **change these immediately**

---

## Disable UPnP

**Via web UI (Velop and WRT series):**
1. Go to **Security** → **Apps and Gaming** → **UPnP**
2. Set UPnP to **Disabled**
3. Click **Save Settings**

**Via Linksys app:**
1. Open the Linksys app
2. Tap your router → **Advanced Settings** → **UPnP**
3. Toggle off and save

---

## Review and remove port forwarding rules

1. Go to **Security** → **Apps and Gaming** → **Single Port Forwarding**
2. Review all listed rules
3. Uncheck **Enabled** on any rules you did not create
4. Click **Save Settings**

Also check:
- **Port Range Forwarding** tab
- **Port Range Triggering** tab

---

## Disable remote management

1. Go to **Security** → **Administration** → **Management**
2. Set **Remote Management** to **Disabled**
3. Click **Save Settings**

---

## Update firmware

1. Go to **Security** → **Administration** → **Firmware Upgrade**
2. Click **Check for Updates**
3. If available click **Start Upgrade**

> Many Linksys vulnerabilities are patched in recent firmware.
> Keeping firmware up to date is the single most important step for Linksys devices.

---

## Verify the fix

After making changes run Muhafiz again.
The correlation should no longer appear if the port has been closed successfully.