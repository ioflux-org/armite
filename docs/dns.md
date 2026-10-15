# Hostnames

Every client talks to Armite by hostname, the way it talks to Azure:
`management.localhost` and `login.localhost` for ARM and Entra, one
hostname per vault (`kv-demo.vault.localhost`) and per storage account
(`stdemo.blob.core.localhost`, plus the `queue.` and `table.` twins
Terraform probes). The certificate covers all of them with wildcards;
whether they resolve to your machine is up to your resolver.
`armite doctor` reports whether each name resolves to this machine.

Check first:

```bash
getent hosts anything.vault.localhost    # Linux, WSL
dscacheutil -q host -a name anything.vault.localhost   # macOS
nslookup anything.vault.localhost        # Windows
```

If that prints `127.0.0.1`, nothing to do.

| platform                                                          | `*.localhost` out of the box | one-time fix                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Linux with systemd-resolved (Ubuntu, Fedora, Arch, most desktops) | yes, any depth               | none                                                                                                                                                                                                                                                                                                                                                                     |
| WSL2                                                              | no                           | resolved usually runs (`resolvectl query x.localhost` answers), but WSL points `/etc/resolv.conf` straight at the Windows DNS and glibc never asks resolved. `sudo apt install libnss-resolve`, then in `/etc/nsswitch.conf` make the line `hosts: files resolve [!UNAVAIL=return] dns`. Needs systemd enabled in the distro (`[boot] systemd=true` in `/etc/wsl.conf`). |
| macOS                                                             | no                           | `brew install dnsmasq`, put `address=/localhost/127.0.0.1` in its configuration, start it, and create `/etc/resolver/localhost` containing `nameserver 127.0.0.1`                                                                                                                                                                                                        |
| Windows                                                           | recent versions: yes         | none; older versions use hosts entries                                                                                                                                                                                                                                                                                                                                   |

After the fix, every name under `.localhost` resolves, forever: no
entries per vault or account.

## Hosts entries instead

Without a resolver fix, add one line per name to `/etc/hosts` (Windows:
`C:\Windows\System32\drivers\etc\hosts`; WSL2: set `generateHosts = false`
in `/etc/wsl.conf` first, or WSL rewrites the file). The server prints
them — the fixed names, then one per vault and per storage account that
exists, the queue and table twins included for Terraform — and it works
beside a running server:

```bash
armite hosts                       # or: go run ./cmd/armite hosts
armite hosts | sudo tee -a /etc/hosts
```

```text
# armite hosts: append to /etc/hosts, or see docs/dns.md for a resolver fix
127.0.0.1  management.localhost
127.0.0.1  login.localhost
127.0.0.1  kv-demo.vault.localhost
127.0.0.1  stdemo.blob.core.localhost
127.0.0.1  stdemo.queue.core.localhost
127.0.0.1  stdemo.table.core.localhost
```

Hosts files have no wildcards, so every new vault or account needs its
own line: re-run it after creating one.

## A public wildcard instead

Any DNS name that resolves to 127.0.0.1 works, including public wildcard
services such as sslip.io, at the price of needing internet DNS and
trusting a third party:

```yaml
vault_host: vault.127-0-0-1.sslip.io
blob_host: blob.core.127-0-0-1.sslip.io
```

The certificate follows the configuration, so nothing else changes.

## Docker

A client in another container does not share the host's resolver. Put it
on the same compose network as Armite and give it the names as
`extra_hosts` entries pointing at the `armite` service, one per vault
or account, or run a resolver in the network.
