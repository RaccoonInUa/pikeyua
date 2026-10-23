# V6 → V7.1 controlled USB cutover — Raspberry Pi Zero W

**Experimental acceptance procedure, not a production deployment.** The cutover touches the USB FIDO2 device only; it does not modify networking, SSH, Device Tree, boot settings, or the original V6 unit file.

## Constraints and recovery limits

- One Pi Zero W has one UDC, `20980000.usb`. V6 and V7.1 cannot bind it simultaneously. The handover stops one Java service and unbinds the existing ConfigFS `fido2` gadget before starting the other.
- Rollback restores **V6 software and USB enumeration** from a verified backup. It cannot reconstruct V6 credentials that only existed in the stopped JVM's RAM. V6 previously failed to write `config.json`; do not rely on previous V6 WebAuthn registrations after switching.
- V7.1 uses separate private state in `/var/lib/pikeyua/config.json` and `config.json.identity`. It is never mixed with V6 or copied to Git.
- A 25-minute *trial timer* is enabled and armed **before** V6 stops. An unconfirmed trial automatically attempts rollback, including after a reboot. Startup failures also trigger best-effort immediate rollback. A broken SD card, missing Wi-Fi, or physically inaccessible Pi cannot be recovered automatically.
- At this version, only ordinary non-discoverable credentials (RK discouraged, UV discouraged) are supported. This software authenticator has no secure element and no real hardware touch verification. Use test accounts only.

## Prepare (no service interruption)

Use the CI-built **JDK17** `pikeyua.jar` corresponding to the V7.1 candidate; don't assume a GitHub "Source code" archive contains the built jar. Copy it from Mac:

```sh
scp ./pikeyua.jar key@192.168.88.17:/home/key/pikeyua-v7.1-smoke.jar
```

On the Raspberry via **Wi-Fi SSH**, preferably in a second terminal so at least one session remains available:

```sh
git clone -b v7.1-persistence https://github.com/RaccoonInUa/pikeyua.git ~/pikeyua-deploy
cd ~/pikeyua-deploy
sudo bash scripts/install-cutover.sh /home/key/pikeyua-v7.1-smoke.jar
sudo pikeyua-cutover status
sudo pikeyua-cutover preflight
```

Installer: runs independent-JVM synthetic credential tests **before any USB change**, locates and SHA-256 backs up the original V6 jar, saves its systemd unit/drop-in, copies V7.1 to `/opt/pikeyua/v7.1/pikeyua.jar`, creates root-owned private directories, and installs an independent V7.1 service and rollback timer. It does **not** stop V6.

**Stop if preflight fails**. It checks the V6 service is enabled and active, Wi-Fi has IPv4, USB is enumerated (`configured`), ConfigFS gadget VID/PID/report length match expected values, and backup checksums match. Do not manually detach the USB gadget beforehand.

## Controlled 25-minute trial

Keep the USB data cable connected to the Mac, and keep Wi-Fi SSH functional.

```sh
sudo pikeyua-cutover switch
sudo pikeyua-cutover status
```

The controller arms a systemd rollback timer, disables V6 autostart, enables V7.1 autostart, stops V6, writes an empty value to `fido2/UDC`, and starts V7.1. It waits for an active matching JVM process, a bound `UDC`, `/dev/hidg0` open, and `configured`.

On the Mac, perform **the real application-level qualification**:

```sh
fido2-token -L
fido2-token -I 'ioreg://CURRENT_DEVICE_ID'
```

Then use https://webauthn.io with a **new TEST username**, `Resident Key / Discoverable Credential = Discouraged` and `User Verification = Discouraged`. Perform **Register and Authenticate**, and confirm both on the site. These browser tests cannot be fully validated by the Pi-side PID/HID health check alone.

If either test fails, restore immediately:

```sh
sudo pikeyua-cutover rollback
sudo pikeyua-cutover status
```

If BOTH pass, **within 25 minutes of the switch**:

```sh
sudo pikeyua-cutover confirm
sudo pikeyua-cutover status
```

Confirmation disables the automatic rollback timer, leaving V7.1 enabled and the V6 backup intact. The controller never shows or uploads credential contents.

## Reboot persistence

**Only after confirming and after initial Register + Authenticate success**, reboot V7.1:

```sh
sudo reboot
```

Reconnect via Wi-Fi SSH and inspect:

```sh
sudo pikeyua-cutover status
stat -c '%a %U:%G %n' /var/lib/pikeyua /var/lib/pikeyua/config.json /var/lib/pikeyua/config.json.identity
sudo journalctl -u pikeyua-v7.service -b -n 50 --no-pager
```

On the Mac, repeat GetInfo and authenticate with the **same credential registered before reboot**. This is the real end-to-end persistence acceptance criterion; simply seeing a new USB device is insufficient. If broken, rollback manually:

```sh
sudo pikeyua-cutover rollback
sudo pikeyua-cutover status
```

If remote rollback fails, do not repeatedly manipulate both services or delete the ConfigFS gadget: inspect logs and the protected snapshot in `/var/lib/pikeyua-cutover/backup/`. Physical access may be necessary.

## Qualification checklist

- [ ] Independent synthetic test passed; verified V6 JAR/service snapshot exists.
- [ ] Read-only preflight passed, SSH via wlan0; MAC USB cable connected.
- [ ] V7.1 switches without restarting Pi; host accepts CTAP2 GetInfo.
- [ ] TEST WebAuthn Register and Authenticate pass before confirmation.
- [ ] Safety timer successfully disarmed on confirmation.
- [ ] Same credential authenticates after V7.1 reboot; AAGUID remains stable.
- [ ] Manual rollback restores V6 USB enumeration and normal service startup.
- [ ] Private state stays root-only and out of Git.

**Not covered:** realistic SD hardware failure, interrupted two-file state + marker write, ENOSPC, power cuts during writes, and security of secrets against physical extraction. Those remain separate acceptance/security work. The built-in rollback timer is a safety net, not an absolute recovery guarantee.

Kernel ConfigFS specifies writing an empty value to `UDC` to unbind the gadget: https://docs.kernel.org/usb/gadget_configfs.html .
