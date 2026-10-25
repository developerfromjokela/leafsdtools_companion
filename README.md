# LeafSDTools Companion
Small utility for applying patches and other fixes that require more processing power than the navigation unit.
This utility is a helper utility for [LeafSDTools](https://github.com/developerfromjokela/leafsdtools/), but can be used also separately.

## Current features
- Make hidden system partitions visible on SD Card
- Backup and Restore SD card
- Auto-agree telematics consent patch for Clarion QY8xxx (Nissan Leaf ZE0 / ZE1)
  - Ported from [autoagree.py](https://github.com/albertbm/qemu-clarion/blob/qy8-gps/tools/qy8/autoagree.py) by [@albertbm](https://github.com/albertbm) (branch `qy8-gps`, commit `de1c75cd`).
  - Automatically bypasses or accepts the startup navigation consent prompt without writing to NAND.
  - *Note:* The head unit's bootloader executes the nav image from the SD card only when its 512-byte header matches the header installed in NAND. The patched card will boot on vehicles running the corresponding firmware build.

## Windows
Please run the program as administrator, sometimes Windows does some nasty things and writes fail.
