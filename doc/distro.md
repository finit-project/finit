Distro Recommendations
======================

Finit supports two directory layouts for managing service configurations:

1. **Simple layout** - all configuration files directly in `/etc/finit.d/`
2. **Distro layout** - separate `available/` and `enabled/` directories

The distro layout is recommended for distributions that need clear
separation between installed and enabled services, and want to use the
`initctl enable/disable` commands for service management.

## Simple Layout

Finit supports using a flat directory structure:

```
    /etc/
      |-- finit.d/              -- All enabled services
      |    |-- lighttpd.conf
      |     `- *.conf
      |-- finit.conf            -- Bootstrap tasks and services
      :
```

In this layout, you enable a service by placing its `.conf` file in
`/etc/finit.d/` and disable it by removing the file. This works well for
embedded systems or custom setups where services are managed by other tools
or generated dynamically.

> [!NOTE] No tooling support
> The `initctl enable/disable` commands **do not work** with this layout.
> You must manually manage files in `/etc/finit.d/`.

## Distro Layout

Distributions typically want clearer separation between available (installed)
and enabled services. Finit supports this through the `available/` and
`enabled/` subdirectories:

```
    /etc/
      |-- finit.d/
      |    |-- available/      -- Installed but disabled services
      |    |    |-- httpd.conf
      |    |    |-- ntpd.conf
      |    |    `-- sshd.conf
      |    |-- enabled/        -- Enabled services (symlinks)
      |    |     `- sshd.conf  -- Symlink to ../available/sshd.conf
      |-- finit.conf           -- Bootstrap tasks and services
      :
```

In this layout:
- **available/** contains all installed service configurations
- **enabled/** contains symlinks to configurations that should start at boot
- Services are enabled/disabled by creating/removing symlinks

> [!IMPORTANT] Recommended
> This is the recommended layout.  In fact, the `initctl enable/disable`
> commands **require** this layout with both `available/` and `enabled/`
> directories and will not work without it.

## Managing Services with initctl

When using the distro layout, the `initctl` tool provides convenient commands
for managing service configurations:

```
   list              List all .conf in /etc/finit.d/
   enable   <CONF>   Enable .conf by creating symlink in enabled/
   disable  <CONF>   Disable .conf by removing symlink from enabled/
   reload            Reload *.conf in /etc/finit.d/ (activate changes)
```

Example usage:

```bash
# Enable sshd (creates enabled/sshd.conf -> ../available/sshd.conf)
initctl enable sshd

# Disable httpd (removes enabled/httpd.conf symlink)
initctl disable httpd

# Apply changes (reload configuration and start/stop services)
initctl reload
```

The `.conf` suffix is optional - `initctl` adds it automatically if missing.

> [!NOTE] Remember `initctl reload`
> Changes made with `enable`/`disable` take effect only after running
> `initctl reload`, unless Finit was built with `--enable-auto-reload`
> which automatically detects and applies configuration changes.

### Service Overrides

The `initctl` tool only operates on symlinks in the `enabled/` directory.
If you place a regular (non-symlink) `.conf` file directly in the parent
directory (e.g., `/etc/finit.d/`), `initctl` will ignore it. This allows
you to create system-level overrides that cannot be accidentally disabled
by package management tools.

### Runtime Control Without Enabling

By default, a `.conf` that only exists in `available/` is not loaded at
all, so `initctl start` cannot control it -- enabling (load) and starting
at boot are one and the same switch.  Products that need the systemd-like
separation between "starts at boot" and "can be started/stopped at
runtime" can enable the `load-available` setting in `/etc/finit.conf`:

```
load-available = true
```

With this setting, unit stanzas in `available/` are loaded with an
internal available-only source state: they show up in `initctl status`
and can be started and stopped freely, yet they do not start
automatically until enabled.  This state is independent of the unit's
`manual-start` option.  Top-level settings in an available-only file
remain inactive.  Enabling the file activates those settings and makes
the unit follow `manual-start`; disabling it no longer makes a service
uncontrollable (a running instance is not stopped by `initctl reload`,
mirroring `systemctl disable`).  See
[config/files.md](config/files.md#loading-available-services) for
details.

## Customizing Directory Paths

Distributions can customize the directory names and locations at build time
using the Finit `configure` script:

```sh
./configure --with-rcsd=/etc/init.d --with-config=/etc/init.d/init.conf
```

This changes the default `/etc/finit.d/` to `/etc/init.d/` and moves the
bootstrap configuration file accordingly.

> [!IMPORTANT] Remember to set `--prefix`
> Remember to set `--prefix` and related options appropriately. The default
> prefix is `/usr/local`, which is likely not what you want for a system
> init. See the [build documentation][1] for details.

Example with custom paths:

```
    /etc/
      |-- init.d/
      |    |-- available/      -- Installed services
      |    |    |-- httpd.conf
      |    |    |-- ntpd.conf
      |    |    `-- sshd.conf
      |    |-- enabled/        -- Enabled services (symlinks)
      |    |     `- sshd.conf  -- Symlink to ../available/sshd.conf
      |     `- init.conf       -- Bootstrap tasks and services
      :
```

Notice how both the service directory and bootstrap configuration file now
use the custom `/etc/init.d/` path specified at build time.

[1]: build.md#configure
