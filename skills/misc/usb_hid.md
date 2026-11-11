# USB HID capture (keyboard / mouse) decode

## When this fits
A `.pcap/.pcapng` whose protocol hierarchy (`tshark -r cap -q -z io,phs`) is dominated by
**USB** (no IP traffic), usually a **keyboard** or **mouse** capture. The flag was *typed*
or *drawn* and lives in the HID report payloads, not in any stream. This is a decoding
problem on top of `pcap.md`'s tooling (tshark is in this image).

## Pull the HID report bytes
Report payloads land in `usb.capdata` or `usbhid.data` depending on tshark version and
capture type — try both:
```
tshark -r cap.pcap -Y 'usb.capdata'  -T fields -e usb.capdata
tshark -r cap.pcap -Y 'usbhid.data'  -T fields -e usbhid.data
```
Multiple devices are usually present (hub, keyboard, mouse). **Isolate the right device
first** — list addresses/endpoints (`-e usb.device_address -e usb.endpoint_address`) and
keep only the interrupt-IN endpoint of the HID device; mixing devices corrupts the decode.

## Keyboard HID (8-byte reports)
Each report is `[modifier, reserved, key1, key2, key3, key4, key5, key6]`.
- `key1` is the active **usage code**; `0x00` = no key (release). Walk reports in order,
  emit one character per non-zero keypress.
- Map usage codes with the standard HID keyboard usage table: `0x04..0x1d` = `a..z`,
  `0x1e..0x27` = `1 2 3 4 5 6 7 8 9 0`, plus `0x2c` space, `0x2d` `-`, `0x2f`/`0x30`
  brackets, `0x28` enter, etc.
- `modifier` bit for **Shift** (`0x02` left / `0x20` right) selects the shifted character
  (`a`→`A`, `1`→`!`, …) — apply it per report. Flags are frequently typed in a shell/box,
  so expect the `flag{...}` / `{ }` shifted symbols.

## Mouse HID
Reports carry `[buttons, dx, dy, (wheel)]` with **signed** deltas. Integrate `dx,dy` into an
(x,y) path; record points while a button is held. Plotting the path (numpy + matplotlib if
present, else dump points and render) reveals a **drawn flag** — the classic "the flag is
sketched by the cursor" challenge. Watch report length: tablets/absolute devices report
absolute coordinates, not deltas.

## Failure signals → pivot
- Both field names return nothing → wrong device/endpoint filter, or the capture stores
  data elsewhere (`usbhid.data` vs a vendor report); re-list fields on a single packet
  (`-V`) to find where the payload actually is.
- Decoded text is gibberish → you merged two devices, mismatched the usage table (keypad vs
  main row), or missed the Shift modifier; re-filter to one device and redo.
- It's not HID at all (bulk transfer carrying a file) → carve it like a transferred file via
  `pcap.md` / `archive.md`, not this.

## Verify
The reconstructed text / drawing *is* the flag only once fully decoded and it matches the
expected charset — confirm the complete `flag{...}` before reporting; a partially decoded
stream is not a flag.
