---
status: accepted
---

# A cooldown holds new upstream digests in the tag runway, keeps its state in the registry, and replaces minimumReleaseAge

Malicious upstream releases (compromised maintainers, worm-style npm/PyPI versions baked into images) are usually detected and pulled within hours to days. We want new upstream digests kept out of our registry until that window has passed, with the image scanned and re-matched against the malicious-packages feed during the wait. `policy.minimumReleaseAge` existed but was never used: when the registry sync ran out-of-process, it could only withhold the attestation, not the import, and it measured age from the image's `created` field, which the publisher controls and which reproducible builds set to 1970. With the in-process mirror and the tag runway, we can now hold the import itself.

We decided:

- **The cooldown applies to images, not to individual packages.** An image can't contain a package version published after the image itself, so once we have known an image for N days, everything inside it is at least that old. A per-package cooldown would need a publish-date lookup for every package in every ecosystem, and would only make the gate more precise.
- **The clock is "first seen upstream by our mirror"**, kept per (target repository, digest) in the digest's hold tag; suppline's database stores no clock. The image's `created` field is shown for information only.
- **The tag runway enforces it.** A new digest is copied by digest and scanned straight away. The tag moves, or a new tag is created, only when the digest has both aged and been attested. Brand-new tags are held too, because a new version is the main way a malicious release gets in. When upstream publishes faster than the cooldown, the tag moves to the newest candidate that has aged and been attested. Because a held digest has no version tag, Renovate pointed at our registry never sees it.
- **A held digest is protected from registry GC by a hold tag** (`sha256-<hex>.hold`). It points at a small OCI index that references the held digest and records first-seen, the source repository and the target tag in annotations. At startup the runway rebuilds its candidates and clocks from these hold tags, before the first mirror cleanup runs. Where the annotation and the database disagree, the annotation wins. **This keeps the database safe to throw away.**
- Hold tags are removed when the digest is published or superseded. **They are not removed when the digest is rejected** (policy failure or malicious match): the image must stay in the registry so it can be triaged in suppline. Mirror cleanup keeps hold tags for every digest the runway holds and deletes any others.
- **Config:** `x-cooldown` lives on `defaults` and on each sync entry, off unless set. `x-policy.minimumReleaseAge` is removed without a compatibility shim. A per-digest `x-cooldown-release` entry, written by a "release now" config edit, skips the wait but never the scan or attestation. Without the in-process mirror, the same key only withholds the attestation (`pending`), counting from the digest's first scan.
- **Grandfathering:** a digest that a real tag in the target already points to counts as aged. That applies when a cooldown is first switched on and when the database is rebuilt. It needs the mirror: without it, there is no hold tag to tell a new digest from an old one.

## Considered Options

How to keep a held digest from being garbage-collected while it's untagged:

- **Self-healing only** (re-copy and re-scan any held digest that disappears): rejected as the main mechanism because aggressive GC would cause repeated re-copies and slip publication. It stays as a check before publishing, as a backstop.
- **Quarantine repository** (hold in `<repo>/quarantine`, then promote by cross-repo copy): rejected because referrers don't follow the copy, so every promotion would need a new attestation.
- **Operator documentation only** (set untagged retention ≥ cooldown): rejected because correctness would depend on configuration outside suppline.
- **A plain hold tag pointing straight at the digest**: rejected because a database wipe would then lose every first-seen clock and candidate, and cleanup would delete the unknown hold tags.

## Consequences

- Registries that reject an OCI index nested inside another index can't use the cooldown. There's no fallback: creating the hold fails, the same as a failed copy.
- Pointing Renovate at the upstream registry instead of our mirror bypasses the cooldown completely. The docs recommend Renovate's own `minimumReleaseAge` as a second layer.
- Held digests can be pulled by digest. Without an attestation, cluster admission policy blocks them.
