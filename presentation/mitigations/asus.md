# ASUS Router — Remediation Guide

## Accessing the admin panel

1. Open a browser and go to `http://192.168.1.1` or `http://router.asus.com`
2. Log in with your admin credentials
3. Default credentials (if never changed): `admin` / `admin` — **change these immediately**

---

## Disable UPnP

1. Go to **Advanced Settings** → **WAN**
2. Click the **Internet Connection** tab
3. Scroll down to **Enable UPnP** → set to **No**
4. Click **Apply**

---

## Review and remove port forwarding rules

1. Go to **Advanced Settings** → **WAN**
2. Click the **Virtual Server / Port Forwarding** tab
3. Review all listed rules
4. Delete any rules you did not create by clicking the **delete** icon
5. Click **Apply**

---

## Disable remote management

1. Go to **Advanced Settings** → **Administration**
2. Click the **System** tab
3. Set **Enable Web Access from WAN** to **No**
4. Click **Apply**

---

## Update firmware

1. Go to **Administration** → **Firmware Upgrade**
2. Click **Check** to see if a newer version is available
3. If available, click **Upgrade** and wait for the router to restart

---

## Enable firewall logging (ASUS AiProtection)

1. Go to **AiProtection** → **Network Protection**
2. Enable **Router Security Assessment**
3. Enable **Malicious Sites Blocking** and **Two-Way IPS**

---

## Verify the fix

After making changes run Muhafiz again.
The correlation should no longer appear if the port has been closed successfully.