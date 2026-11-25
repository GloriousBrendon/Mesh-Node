# A rented server for the second seed: what it needs

Written 2026-11-14, before anything is rented; changed 2026-11-25, when the
home seed became relay-only. This lists requirements only, not a provider.
It covers the seed of `compose.yaml`, run as at home: `--relay-only --relay
<n0's EU relay> --mail --mail-max 2147483648` (SPEC-seed D8c as changed), for
a beta of about ten people. There's no relay of our own any more: callers
reach the seed through n0's relay. The figures come from PLAN-mailbox Task 16
and SPEC-seed unless marked as estimates.

## Must have

- **Outbound internet only.** A relay-only seed dials out to its relay and
  opens no port, so it needs no fixed or public address, no port forward
  and no domain. Its ticket (compiled into every `mesh-node`,
  `helper::SEEDS`) names its key and its relay, never an address.
- **Nothing open inbound.** Admin is ssh over Tailscale (D10), which needs
  only outbound traffic too.
- **Root or Docker access** to run the container. `mesh-seed.service` is
  there for running without Docker.
- A seed that should take callers direct instead runs with `--port` and
  `--public` (D8c), and then needs a public IPv4 address that never changes
  and that UDP port open; not the plan for now.

## Sizes

- **Memory: 1 GB is enough for the beta; 2 GB for headroom.**
  - The seed holds its mail index in memory. Measured: 200 MB for 1,100
    people at scale, with a 338 MB store.
  - Ten people put about 2.6 MB each on disk, so the index stays in the tens
    of MB.
  - A store filled to its 2 GiB cap would hold an index of roughly 1.2 GB.
    That's an estimate, scaled from the measurement.
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
- **Relayed traffic between people goes over n0's relays**, not this
  server. All of the seed's own traffic goes through its relay too.
- **What to ask for:** 10 GB a month is plenty; any plan covers it.

## Region

- **Close to its relay.** Every request to the seed crosses n0's relay
  first, so a server near the relay's region (the EU one, for now) keeps
  that leg short. Clients go to the seed's relay at once, with no direct
  try first (D8c as changed).
- **On a different network from home.** The point of the second seed is that
  people away from home can reach it, and that it stays up when the home line
  doesn't. Any provider outside your ISP's network meets that.
- **Jurisdiction:** the seed holds only ciphertext, sizes and times, and logs
  counts only (D10). A live operator can still link sessions and addresses
  (D10b), so pick a provider you'd trust to see who connects to whom, as you
  would for any VPN. Nothing in Mesh needs a particular country.
