# iOS16 bootstrap candidate

BlueTool.c is byte-identical to UniXNU/QcaBluetooth revision
986d6319d1d2819b27ed2c9786776f10bf63cc76, userland/BlueTool.c.
Its BSD-2-Clause-Patent license is included. This workflow compiles only this
open-source helper, for arm64/iOS16. It does not upload Apple binaries, phone
firmware, disk images or trust caches. Compilation does not establish native
Bluetooth compatibility; the local 20H392 daemon adapter is a separate input.
