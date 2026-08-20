Service Environment
-------------------

Finit supports sourcing environment variables from `/etc/default/*`, or
similar `--with-sysconfig=DIR`.  This is a common pattern from SysV init
scripts, where the start-stop script is a generic script for the given
service, `foo`, and the options for the service are sourced from the
file `/etc/default/foo`.  Like this:

* `/etc/default/foo`:

        FOO_OPTIONS=--extra-arg="bar" -s -x

* `/etc/finit.conf`:

        service foo {
            description = "Example foo daemon"
            runlevel    = "2345"
            envfile     = "-/etc/default/foo"
            command     = "foo -n $FOO_OPTIONS"
        }

Here the service `foo` is started with `-n`, to make sure it runs in the
foreground, and the with the options found in the environment file.  With
the `ps` command we can see that the process is started with:

    foo -n --extra-arg=bar -s -x

> [!NOTE]
For a service with [`pam`](pam.md), the session environment is applied
before `envfile`, so the file overrides anything `pam_env` set.

> The leading `-` on `envfile` determines if Finit should treat a
> missing environment file as blocking the start of the service or not.
> When `-` is used, a missing environment file does *not* block the
> start.  The same mark works on `command`, where it means carry on if
> the binary is missing.
