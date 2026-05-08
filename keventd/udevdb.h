/* udev-compatible per-device database in /run/udev/data/
 *
 * Copyright (c) 2025  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef KEVENTD_UDEVDB_H_
#define KEVENTD_UDEVDB_H_

#include "keventd.h"

/*
 * Database root directory, compatible with systemd/eudev's /run/udev/data/.
 * One text file per device, keyed by device ID (see udevdb_path()).
 *
 * Record format (one per line):
 *   I:<usec>         initialisation timestamp
 *   E:<KEY>=<VAL>    environment / property
 *   S:<path>         symlink (relative to /dev/)
 *   G:<tag>          tag (for G: records)
 *   Q:<tag>          tag (for Q: query records, mirrors G:)
 *   V:1              format version sentinel, always last
 */
#define UDEVDB_PATH  "/run/udev/data"

/*
 * Write a device's properties to the database after event processing.
 * Creates /run/udev/data/<id> with I:, E:, S:, G:, Q:, V: records.
 */
int  udevdb_write  (const struct uevent *ev);

/*
 * Read a device's properties from the database into ev's env store.
 * Used by IMPORT{db} and IMPORT{parent} in the rules engine (Phase 4).
 */
int  udevdb_read   (struct uevent *ev);

/*
 * Like udevdb_read(), but for the parent device of ev.
 */
int  udevdb_read_parent (struct uevent *ev);

/*
 * Delete a device's database entry on ACT_REMOVE.
 */
void udevdb_delete (const struct uevent *ev);

#endif /* KEVENTD_UDEVDB_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
