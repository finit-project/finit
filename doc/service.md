Starting & Monitoring
=====================

Finit can start and monitor the following types of daemons:

  * Forks to background, creates a PID file
  * Runs in foreground and signals ready by:
    - creating a PID file
    - does not create a PID file -- Finit can create it for you (optional)
    - [other mechanism][1] (systemd, s6)

Finit can *not* start and monitor a daemon that:

  * Forks to background and does *not* create a PID file

|   | Forking | Creates PID File | Finit creates PID File |
|---|---------|------------------|------------------------|
| ✔ | Yes     | Yes              | No                     |
| ✔ | No      | Yes              | No                     |
| ✔ | No      | No               | Yes, optionally        |
| ✘ | Yes     | No               | No                     |

> [!NOTE]
> PID files is one mechanism used to assert conditions to synchronize
> the start and stop of other, dependent, services.  Other mechanisms
> are described in the [Service Synchronization][1] section.

### Forks to bg w/ PID file

There are two variants.  The former names the pidfile to watch, as for
`sysv` start/stop scripts, and the latter is inspired by systemd, with a
twist -- it lets Finit guess the pidfile based on the standard path and
the basename of the command.

    service serv {
        description = "Forking service, type 1"
        pidfile     = "/run/serv.pid"
        command     = "serv"
    }

    service serv {
        description = "Forking service, type 2"
        type        = "forking"
        command     = "serv"
    }

In this example the resulting files to watch for are `/run/serv.pid` and
`/var/run/serv.pid`, respectively.  On most modern Linux systems this is
the same directory (`/var/run` is a symlink to `../run`).

### Runs in fg w/ PID file

    service serv {
        description = "Foreground service w/ PID file"
        command     = "serv -n -p"
    }

### Runs in fg w/o PID file

Same as previous, but we tell Finit to create the PID file, because we
need it to synchronize start/stop of a dependent service.

    service serv {
        description    = "Foreground service w/o PID file"
        pidfile        = "/run/serv.pid"
        pidfile-create = true
        command        = "serv -n"
    }

### Runs in fg w/ custom PID file

    service serv {
        description = "Foreground service w/ custom PID file"
        pidfile     = "/run/servy.pid"
        command     = "serv -n -p -P /run/servy.pid"
    }

[1]: config/service-sync.md
