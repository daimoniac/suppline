---
status: accepted
---

# A newest-N tag window, ordered by image build time, with cleanup keeping running tags

CI-built repositories tag every build with a commit hash (`sha1a2b3c4d`). They hold hundreds of tags, and the names have no version order, so `semverRange` cannot narrow them. Mirroring such a repository with an `allow` regex copies and scans its whole history, then rescans every copy each `rescanInterval`. We want only the recent builds.

We decided:

- **`tags.newest: N`** keeps the N tags built last, after `allow`, `deny` and `semverRange`. It is a selection over the filtered list, not a per-tag predicate, so code that asks "does this entry allow this tag?" (sync identity) ignores it.
- **Order comes from the image config's `created` field.** It is the only build time every registry exposes. ADR 0001 rejected `created` as a cooldown clock because the publisher controls it. Here it only chooses which tags to copy: a wrong or forged time can shift the window, but every copied image is still scanned and gated. Ties, including reproducible builds that fix `created`, go to the higher tag name.
- **Mirror and cleanup use the same window.** Cleanup applies `newest` to the target's tags. They are copies of the same digests, so they sort the same way, and tags that fall out of the window are deleted.
- **Build times are cached in memory only**, per repository and tag, for 24 hours. A restart reads them again, so the database stays safe to throw away.
- **`cleanupKeepRunning`** keeps target tags that the latest report of any clusterstate-agent cluster runs. Release images run longer than develop builds take to push them out of a window. Without this, cleanup would delete the tag of an image still deployed, and the next pod reschedule could not pull it. When no cluster has reported, cleanup deletes no tag it would otherwise delete, because it cannot tell which ones run.

## Considered Options

- **Order by when suppline first saw a tag**: on the first pass every tag is seen at the same moment, so there is no order exactly when the window matters most. It also needs state the database is allowed to lose.
- **Skip tags that existed when the entry was added** ("no backfill"): needs a stored baseline, lost with the database, and gives no rolling retention.
- **The registry's own tag timestamps** (GitLab's tags API `created_at`): registry-specific.
- **Extra CI tags** (branch or release names) filtered by `allow`: needs CI changes in every source project and still sets no limit on how many tags are kept.
- **A maximum age instead of a count**: a count bounds copy and scan cost regardless of how often CI builds. Age can be added later if needed.

## Consequences

- The first pass after a restart reads the build time of every candidate tag: about two registry requests per tag.
- A failure to read one tag's build time fails that repository's pass, both for copying and for cleanup. Cleanup never deletes on a guessed order.
- Tags are kept by repository and tag name. A pod that pulls only by digest does not keep its tag.
