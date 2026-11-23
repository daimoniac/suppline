# suppline

Supply-chain scanning of container images: repositories, tags, scans, vulnerabilities, and VEX.

## Language

**Page Size**:
The number of items shown on one page of any paged list in the UI. One Page Size applies to all paged lists for a given browser.
_Avoid_: limit (API query param), per-list page size, items-per-page as a separate setting per list

**Runtime usage**:
The current presence of an image in the inventory reported by one or more clusters, including where the image is running.
_Avoid_: deployment status, scan activity, registry presence

**Current tag binding**:
The digest a repository tag currently identifies. A tag has one current binding even when it previously identified other digests.
_Avoid_: latest scan, newest tag, tag history

**Tag runway**:
The path a mirrored digest takes onto a tag: copied by digest, held while a Scan request attests it and its Cooldown runs, then published by moving or creating the tag. A Held digest never takes the tag's Current tag binding before the registry tag names it.
_Avoid_: promotion, tag gate, retag

**Cooldown**:
The minimum time between suppline first seeing a digest upstream and that digest being published on a tag. It counts from suppline's own first sighting, never from the image's build date.
_Avoid_: minimum release age, quarantine, maturity, embargo

**Held digest**:
A mirrored digest the Tag runway has not yet published, because its Cooldown is still running, it lacks a passing attestation, or both. A Held digest stays held after a policy failure so it can be triaged, and is dropped only when a newer candidate for the same tag is published.
_Avoid_: pending image, quarantined image, staged digest

**Cooldown release**:
A recorded decision to skip the rest of one Held digest's Cooldown. It never skips the scan or the attestation.
_Avoid_: bypass, override, fast-track

**Newest window**:
The N tags of a sync entry's tag set whose images were built last, by the image's `created` field. The mirror copies only these, and cleanup deletes target tags that fall out of it unless a cluster runs them (Runtime usage).
_Avoid_: tag limit, retention count, latest N

**In-place entry**:
A repository suppline scans and attests in the registry it was pushed to, without copying it. Its tags are chosen by the entry's tag filters plus the tags a cluster runs; it has no Cooldown and no Tag runway.
_Avoid_: unmirrored sync, local repository, own image

**Scan request**:
An expressed intent to scan a specific container image, whether discovered automatically or initiated as a rescan.
_Avoid_: queue task, worker job

**Repository policy**:
The effective security rules and vulnerability-exemption decisions that apply to images in one repository.
_Avoid_: sync configuration, scan policy lookup

**Triage statement**:
One CVE on one repository, shown whether it is an exemption or a triage run that has not become an exemption.
_Avoid_: VEX row, triage line

**Open triage**:
A triage run that still needs an exemption written: the verdict is uncertain, or the run was rejected or failed, and a later run has not replaced it.
_Avoid_: dry run, auto filter

**Running configuration**:
The suppline.yml content in force right now: the startup file plus every reload and config edit since. Readers take a fresh snapshot per decision; a snapshot never changes after it is handed out.
_Avoid_: startup config, regsync config (for the live state), cached config

**Config edit**:
One change to suppline.yml made by suppline itself (a triage statement, a manual override, a task fix): written to the config repository or local file, applied to the Running configuration, and followed by a rescan of every repository whose Repository policy changed.
_Avoid_: commit config, hot-swap, applyMemory
