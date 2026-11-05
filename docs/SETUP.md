# Setting up homelink

This guide takes you from nothing to connected. You need two computers:

- the **host**: the computer whose internet you want to use (for example, your
  home PC). It must stay on while you use homelink.
- the **client**: the computer you're using somewhere else (for example, your
  laptop at school or work).

Either one can be a Mac or a Windows PC. Everything here is free.

---

## 1. Install homelink on both computers

Download the latest installer from the project's **Releases** page on GitHub:

- macOS: `homelink_<version>_universal.dmg`
- Windows: `homelink_<version>_x64-setup.exe`

homelink isn't signed by Apple or Microsoft (that costs money every year), so
each system warns you once. This is expected.

### macOS

1. Open the `.dmg` and drag **homelink** into **Applications**.
2. Open homelink from Applications. macOS says it can't verify the developer.
   Click **Done** (or **Cancel**).
3. Open **System Settings → Privacy & Security**, scroll down, and click
   **Open Anyway** next to the homelink message. Confirm with your password.
4. homelink opens. From now on it opens normally.

If macOS says the app "is damaged and can't be opened", run this once in
Terminal, then open it again:

```sh
xattr -dr com.apple.quarantine /Applications/homelink.app
```

### Windows

1. Run `homelink_<version>_x64-setup.exe`.
2. If **Windows protected your PC** appears, click **More info → Run anyway**.
3. Allow the installer to make changes (it needs admin rights once, to add the
   firewall rules homelink needs).
4. If your antivirus questions the file, choose to allow it.

homelink lives in the system tray (Windows) or menu bar (macOS). Closing the
window keeps it running; use the tray icon → **Quit** to exit.

---

## 2. Check the host's internet connection can be reached

On the **host**, open homelink → **Share** → **Network check** → **Check my
network**.

- **"port forwarding should work"**: continue to step 3.
- **"uses CGNAT"**: your internet provider shares one public address between
  many customers, so nobody can connect in. Ask your provider for a **public
  IPv4 address** (some give it free on request, some charge). Without one,
  this connection can't be a host. Use a different host location instead.
- **"two routers"**: you have a modem-router plus your own router. Either set
  the first one to *bridge mode*, or forward the port on both (step 3).
- **"Couldn't ask your router"**: automatic forwarding is off. Do step 3 by
  hand, then test (step 3d).

---

## 3. Port forwarding on the host's router

homelink uses **port 47420, both UDP and TCP**, forwarded to the host computer.

### 3a. Try the automatic way first

On the host, click **Start sharing**. Under *Router* homelink shows either:

- **"Port forwarded automatically by your router."** Done; skip to step 4.
- Something like *"no UPnP router found"*. Do it by hand (3b).

### 3b. Find the host's local address

The host's local (LAN) address is shown in **Network check** as *This
computer*, e.g. `192.168.1.23`.

So that it doesn't change later, reserve it in your router: look for **DHCP
reservation**, **Address reservation** or **Static lease**, and reserve that
address for the host computer.

### 3c. Add the forwarding rule

1. Open your router's settings page in a browser. It's usually
   `http://192.168.1.1`, `http://192.168.0.1` or `http://10.0.0.1`; the
   address and password are often on a sticker on the router.
2. Find the section called **Port Forwarding**, **Virtual Server**, **NAT** or
   **Applications & Gaming** (often under *Advanced*).
3. Add a rule:

   | Field | Value |
   | --- | --- |
   | Name / Service | homelink |
   | Protocol | **Both** (TCP and UDP). If you must choose one, add two rules. |
   | External / WAN port | 47420 |
   | Internal / LAN port | 47420 |
   | Internal IP / Device | the host's address from 3b |

4. Save. Some routers need a restart.

Changing the port: if 47420 is taken or you want another, set it under
**Sharing settings → Port** on the host and forward that port instead.

### 3d. Mac hosts: allow incoming connections

If the macOS firewall is on (*System Settings → Network → Firewall*), the
first time you click **Start sharing** macOS asks whether homelink may accept
incoming network connections. Click **Allow**. If you missed it, add homelink
under *Firewall → Options* and set it to *Allow incoming connections*.

(Windows doesn't ask: the installer already added the firewall rules.)

### 3e. Test it

Test from **outside** the host's network: after finishing step 5, connect from
a **phone hotspot** or another Wi-Fi. Many routers can't connect a device to
their own public address from inside the same network ("hairpin NAT"), so a
test from home can fail even when everything is set up right.

---

## 4. Keep the host available

- **Don't let it sleep.**
  - Windows: *Settings → System → Power* → set *Sleep* to **Never** when
    plugged in.
  - macOS: *System Settings → Battery/Energy* → turn on **Prevent automatic
    sleeping when the display is off** (or *Options…* on laptops).
- In homelink → **Sharing settings**, turn on **Start sharing when homelink
  opens** and **Open homelink when I log in**, then click **Save**. After a
  restart the host shares again on its own once you log in.

### Optional: a name that survives IP changes (DDNS)

Most home internet connections get a new public IP now and then. When that
happens, saved hosts stop working until you send a new invite. To avoid this,
get a free hostname that follows your IP:

- Many routers have **Dynamic DNS** built in (look for *DDNS*), or
- use a free service such as **DuckDNS** (duckdns.org) with its updater.

Then put the name (e.g. `myhome.duckdns.org`) in **Sharing settings →
Address for invites** and click **Save**. New invites use it.

---

## 5. Pair the client

1. On the **host**: **Share → Invite a device → Copy**. The code works once and
   expires in 15 minutes.
2. Send the code to yourself (message, email, notes app).
3. On the **client**: **Connect → Add a host**, paste the code, give it a name
   (e.g. *Home*), and click **Add**.
4. On the host, a window asks whether to allow the new device. Click
   **Allow**.

The client now lists the host under **Hosts**.

---

## 6. Connect

On the client, choose how traffic should go under **When connected**:

| Mode | What goes through the host | Password? |
| --- | --- | --- |
| **System proxy** (default) | Browsers and most apps | No |
| **Full tunnel** | Everything, including games, calls and apps that ignore proxy settings | Yes, each time you connect |
| **SOCKS5 proxy only** | Only apps you point at `127.0.0.1:1080` | No |

Click **Connect** next to the host. The top card shows *Connected to …*, the
ping, and the current speed. If it says *via TCP*, the network you're on blocks
UDP; homelink switched to TCP by itself (it's a little slower to open new
connections).

To check it's working, visit a "what is my IP" website: it should show the
host's internet address.

Click **Disconnect** when you're done. Your normal settings come back.

---

## Troubleshooting

| Problem | What to try |
| --- | --- |
| *"The host … didn't answer"* | Is the host on, awake, and **sharing**? Is port 47420 forwarded for **both TCP and UDP**? Did the host's IP change (see DDNS above)? On the host, *Network check* should say forwarding can work. |
| *"Your public address changed"* on the host | Send a new invite (pasting it on an already-paired client just updates the address, no approval needed), or use **Edit** on the client to enter the new address, or set up DDNS. |
| *"The host doesn't know this device"* | The device was removed on the host. Create a new invite and add it again. |
| Pairing says the code is *not valid* or *expired* | Codes work once and for 15 minutes. Make a new one. |
| Some app doesn't go through the host | That app ignores the system proxy. Use **Full tunnel**. |
| Internet doesn't work after homelink crashed | **Connect → Trouble? → Repair network settings**. |
| Router page, printer, etc. unreachable while connected | They're on *your* network; homelink leaves local addresses alone in system-proxy mode. In full-tunnel mode, disconnect to reach them. |
| Doesn't connect when the client is on the **same network** as the host | Your router probably doesn't support hairpin NAT. Test from another network, or on the client use **Edit** to set the host's address to its local one (e.g. `192.168.1.23`) while you're at home. |
| Need help | **Copy diagnostics** (under *Network check* or *Trouble?*) and paste the report. IP addresses in it are partly hidden. |

## Uninstalling

- **macOS**: quit homelink (menu bar icon → **Quit**), then drag
  `/Applications/homelink.app` to the Trash. To also remove pairings and
  settings, delete `~/Library/Application Support/homelink`.
- **Windows**: quit homelink (tray icon → **Quit**), then *Settings → Apps →
  Installed apps → homelink → Uninstall* (this also removes its firewall
  rules). To remove pairings and settings, delete `%APPDATA%\homelink`.

Before uninstalling a host, you can remove its devices under **Share →
Devices**; before uninstalling a client, disconnect first.

## Security notes

- Only devices you approved can connect, and you can remove one any time
  under **Share → Devices**.
- Connected devices can't reach the host's local network (printers, NAS,
  router page) unless you turn on **Let devices reach my local network**.
- Everything between client and host is encrypted (TLS 1.3), and each side
  checks the other's device key.
- Anything a connected device does online comes from the host's internet
  address. Only pair devices you trust.
