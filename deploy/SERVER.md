# A rented server for the second seed: what it needs

Written 2026-11-14, before anything is rented. This lists requirements only,
not a provider. It covers the seed and relay of `compose.yaml`, run as at
home: `--mail --mail-max 2147483648`, plus `--port`/`--public` for a fixed
address (SPEC-seed D8c), for a beta of about ten people. The figures come from
PLAN-mailbox Task 16 and SPEC-seed unless marked as estimates.

## Must have

- **A public IPv4 address that never changes.** The seed's ticket carries
  `&addr=<ip:port>` (D8c), and that ticket is compiled into every
  `mesh-node` (`helper::SEEDS`). A new address means a new release for
  everyone, so a static or reserved IP is required, not a dynamic one. IPv6
  is welcome (the seed binds it when present), but not required.
- **Open ports, inbound:**

  | Port | What it's for |
  |---|---|
  | TCP 443 | The relay over HTTPS, behind Caddy or another TLS proxy (D3) |
  | TCP 80 | Only if the certificate uses the HTTP challenge. With the DNS challenge, as at home, it stays closed. |
  | UDP, one port | The seed's own `--port` (D8c), any fixed number |

  Nothing else should be open. Admin is ssh over Tailscale (D10), and
  Tailscale needs only outbound traffic. The relay's QUIC address discovery
  stays off (D4), so it needs no UDP port of its own.
- **A domain name for the relay**, with a DNS record pointing at the address,
  and a certificate for it.
- **Root or Docker access** to run the two containers. `mesh-seed.service`
  is there for running without Docker.
- **Full UDP.** Some cheap hosts filter or rate-limit UDP. The seed's port
  and every iroh hole-punch depend on it.

## Sizes

- **Memory: 1 GB is enough for the beta; 2 GB for headroom.**
  - The seed holds its mail index in memory. Measured: 200 MB for 1,100
    people at scale, with a 338 MB store.
  - Ten people put about 2.6 MB each on disk, so the index stays in the tens
    of MB.
  - A store filled to its 2 GiB cap would hold an index of roughly 1.2 GB.
    That's an estimate, scaled from the measurement.
  - The relay is small: tens of MB.
  - `mesh-seed.service` caps memory at 512 MB. That's fine for ten people,
    but too little for a full 2 GiB store. Raise it if the store grows.
- **Building the image on the server needs more memory than running it.** A
  release Rust build of `mesh-node` wants about 2 to 4 GB of RAM and several
  GB of disk for `target/` (an estimate). On a 1 GB server, build the image
  elsewhere and copy it over with `docker save` and `docker load`.
- **Disk: 10 GB free, 20 GB is comfortable.**
  - Mail store: up to 2 GiB (`--mail-max`). Claims, mail records and
    envelopes count against it together.
  - Room to compact: a log is rewritten to a new file before the old one goes
    (mailstore `sweep()`), so the largest log needs that much again free.
    Allow up to 2 GiB more.
  - Codes, address records and requests: about 20 MB at their caps (D9).
  - Images and container logs: under 1 GB. Docker's default log driver grows
    without bound, so set a log size limit. The seed logs only two lines an
    hour, which is small anyway.
  - Back up the seed's data volume: its key is its identity (D2). Losing it
    means shipping a new ticket in the next release.
- **CPU: one vCPU.** The seed is light. The heaviest single step measured is
  a compaction: 460 ms at 338 MB, under the store's lock.

## Traffic for about ten people (estimates)

- **The seed's own traffic: well under 1 GB a month.** Per person and day:
  - collects: 128 slots every 30 minutes while unlocked, at about 60 bytes
    each, so about 350 KB a day;
  - a daily claim renewal: 384 claims, about 40 KB;
  - mail records: about 800 bytes per friend;
  - mail itself: around ten envelopes of about 1 KB.

  That's about 1 MB a person a day at most: about 0.3 GB a month for ten.
- **The relay carries everything that can't go direct.** That is all traffic
  between two people when hole punching fails, including files of up to
  100 MB (dm D12). iroh relays only until a direct path is found, so most text
  traffic goes direct. Heavy file sharing on a network that blocks punching
  could reach tens of GB a month. Later, `calls` adds about 50 kbit/s per
  relayed voice stream (roughly 22 MB an hour).
- **What to ask for:** 100 GB a month or more, with no surprise overage
  charges. Many plans include 1 TB or more, which covers this many times
  over.
- The relay already limits each client to 2 MB/s steady, with bursts to
  4 MB (`relay.toml`).

## Region

- **Close to the people using it.** iroh chooses a home relay by latency, so
  a nearby relay is the one people actually use. Every relayed message, and
  later every relayed call, crosses it. Clients dial the seed direct for 2 s
  before falling back to its relay (D8c), and a far server spends more of
  that on the handshake. Aim for under about 50 ms from most of the beta's
  homes.
- **On a different network from home.** The point of the second seed is that
  people away from home can reach it, and that it stays up when the home line
  doesn't. Any provider outside your ISP's network meets that.
- **Jurisdiction:** the seed holds only ciphertext, sizes and times, and logs
  counts only (D10). A live operator can still link sessions and addresses
  (D10b), so pick a provider you'd trust to see who connects to whom, as you
  would for any VPN. Nothing in Mesh needs a particular country.
