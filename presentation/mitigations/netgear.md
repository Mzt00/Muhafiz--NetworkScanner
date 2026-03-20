# Netgear Router — Remediation Guide

## Accessing the admin panel

1. Open a browser and go to `http://192.168.1.1` or `http://routerlogin.net`
2. Log in with your admin credentials
3. Default credentials: `admin` / `password` — **change these immediately**

---

## Disable UPnP

**Via web UI:**
1. Go to **Advanced** → **Advanced Setup** → **UPnP**
2. Uncheck **Turn UPnP On**
3. Click **Apply**

**Via Netgear app:**
1. Open the Nighthawk or Orbi app
2. Tap **Settings** → **UPnP**
3. Toggle off and save

---

## Review and remove port forwarding rules

1. Go to **Advanced** → **Advanced Setup** → **Port Forwarding / Port Triggering**
2. Select **Port Forwarding** radio button
3. Review all listed services
4. Select any unwanted rule and click **Delete Service**
5. Click **Apply**

---

## Disable remote management

1. Go to **Advanced** → **Advanced Setup** → **Remote Management**
2. Uncheck **Allow Remote Management**
3. Click **Apply**

---

## Update firmware

1. Go to **Advanced** → **Administration** → **Firmware Update**
2. Click **Check Online** for the latest firmware
3. If available click **Update**

---

## Enable Netgear Armor (if available)

1. Go to **Advanced** → **Security** → **Netgear Armor**
2. Enable Armor for real-time threat protection
3. Review the security dashboard for flagged devices

---

## Verify the fix

After making changes run Muhafiz again.
The correlation should no longer appear if the port has been closed successfully.