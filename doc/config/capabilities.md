Linux Capabilities
==================

Finit supports Linux capabilities, allowing services to run with minimal
required privileges instead of running as root. This significantly improves
system security by following the principle of least privilege.

## Overview

Linux capabilities divide the traditional root privileges into distinct units
that can be independently granted to processes. For example, a web server only
needs the capability to bind to privileged ports (< 1024), not full root access.

Finit uses the modern IAB (Inheritable, Ambient, Bounding) API from libcap,
which is the same approach used by other modern service managers like dinit.

## Basic Usage

Capabilities are specified with the `capabilities` key, alias `caps`:

```conf
service nginx {
    description  = "Web server"
    runlevel     = "2345"
    user         = "www-data"
    group        = "www-data"
    capabilities = { "^cap_net_bind_service" }
    command      = "/usr/sbin/nginx -g 'daemon off;'"
}
```

This example allows nginx to bind to privileged ports (like 80 and 443) while
running as the unprivileged `www-data` user.

## IAB Format

The capability string uses the IAB (Inheritable, Ambient, Bounding) format
with the following prefixes:

- `^` **Ambient** (and Inheritable) - **Recommended for most use cases**
  - Capabilities survive across `exec()` calls
  - Automatically raised to effective after exec
  - Example: `^cap_net_bind_service`

- `%` **Inheritable** only
  - Requires the executed binary to have matching file capabilities
  - Less common, more complex setup
  - Example: `%cap_net_admin`

- `!` **Bounding** - Block capability from bounding set
  - Prevents the service from ever acquiring this capability
  - Useful for security hardening
  - Example: `!cap_sys_admin`

Multiple capabilities can be specified as a comma-separated list:

```conf
capabilities = { "^cap_net_raw", "^cap_net_admin", "^cap_net_bind_service" }
```

## Common Use Cases

### Web Server (Privileged Ports)

Allow a web server to bind to ports 80 and 443 without running as root:

```conf
service webserver {
    runlevel     = "2345"
    user         = "www-data"
    group        = "www-data"
    capabilities = { "^cap_net_bind_service" }
    command      = "/usr/sbin/nginx -g 'daemon off;'"
}
```

### Network Monitoring (Raw Sockets)

Allow packet capture without root privileges:

```conf
service tcpdump {
    runlevel     = "2345"
    user         = "tcpdump"
    capabilities = { "^cap_net_raw", "^cap_net_admin" }
    command      = "/usr/sbin/tcpdump -i eth0 -w /var/log/capture.pcap"
}
```

### NTP Daemon (System Time)

Allow time synchronization without full root:

```conf
service ntpd {
    runlevel     = "2345"
    user         = "ntp"
    capabilities = { "^cap_sys_time", "^cap_sys_nice" }
    command      = "/usr/sbin/ntpd -n"
}
```

## Available Capabilities

Common capabilities include (see `man 7 capabilities` for the complete list):

- `cap_chown` - Make arbitrary changes to file UIDs and GIDs
- `cap_dac_override` - Bypass file read, write, and execute permission checks
- `cap_dac_read_search` - Bypass file read permission checks
- `cap_fowner` - Bypass permission checks on operations that normally require filesystem UID
- `cap_kill` - Bypass permission checks for sending signals
- `cap_net_admin` - Perform various network-related operations
- `cap_net_bind_service` - Bind to privileged ports (< 1024)
- `cap_net_raw` - Use RAW and PACKET sockets
- `cap_setgid` - Make arbitrary manipulations of process GIDs
- `cap_setuid` - Make arbitrary manipulations of process UIDs
- `cap_sys_admin` - Perform system administration operations (very powerful!)
- `cap_sys_module` - Load and unload kernel modules
- `cap_sys_nice` - Raise process nice value and change scheduling
- `cap_sys_time` - Set system clock

## Security Best Practices

1. **Use the minimum required capabilities**
   - Only grant what the service actually needs
   - Don't grant `cap_sys_admin` unless absolutely necessary

2. **Specify a user (preferably non-root)**
   - The `user` setting is **required** for `capabilities` to take effect
   - For ambient capabilities (`^`), use a non-root user (not `"root"`)
   - Example: `user = "www-data"`, `user = "nginx"`, `user = "tcpdump"`

3. **Use ambient capabilities (`^`)**
   - The `^` prefix ensures capabilities survive exec()
   - Simpler than setting file capabilities on binaries

4. **Block dangerous capabilities**
   - Use `!` to explicitly block capabilities you don't want
   - Example: `!cap_sys_admin,!cap_sys_module`

5. **Test with `getpcaps`**
   - After starting a service, verify its capabilities:
     ```bash
     getpcaps $(pidof nginx)
     ```
   - Should show only the capabilities you granted

## Verification

After configuring a service with capabilities, verify it works correctly:

```bash
# Start the service
initctl start webserver

# Check the process capabilities
getpcaps $(pidof nginx)

# Should show something like:
# 12345: cap_net_bind_service=eip

# Verify the user
ps -o user,pid,cmd -p $(pidof nginx)

# Should show the service running as the specified user
```

## Requirements

- Linux kernel 4.3+ (for ambient capabilities support)
- libcap library installed
- Finit built with `--enable-libcap`, otherwise a `capabilities` list is
  ignored, with a warning

## Limitations

- `capabilities` requires `user` to be set for it to take effect
  - Without `user`, the service runs as root with full capabilities and
    the `capabilities` list is silently ignored
  - You can use `user = "root"`, but see below about ambient capabilities
- For ambient capabilities (`^`, recommended), the user **must be non-root**
  - Using `user = "root"` with `^` capabilities will not work effectively, as ambient
    capabilities are only added to the effective set when euid ≠ 0
  - Use inheritable (`%`) or bounding (`!`) capabilities with `user = "root"` if needed
  - Finit warns about this when reading the .conf file:

        nginx: ambient capabilities ('^') have no effect as root, use a
        non-root user, or '%' and '!' entries
- Services without `capabilities` use standard privilege dropping:
  - Services with a non-root `user` have no special capabilities
  - Services without `user` run as root with full capabilities
- A capability granted by `pam_cap.so` in a [PAM session](pam.md) is
  merged into this set, but only when `capabilities` is also set.
  Without it the grant is lost when privileges drop
- Some very old binaries may not work correctly with ambient capabilities
- File system capabilities are not managed by Finit (use `setcap` for that)

## See Also

- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) - Linux capabilities overview
- [cap_iab(3)](https://man7.org/linux/man-pages/man3/cap_iab.3.html) - IAB capability API documentation
- [setcap(8)](https://man7.org/linux/man-pages/man8/setcap.8.html) - Set file capabilities
- [getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html) - Query file capabilities
- [capsh(1)](https://man7.org/linux/man-pages/man1/capsh.1.html) - Capability shell wrapper
