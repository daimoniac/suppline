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
The path a mirrored digest takes onto an existing tag: copied by digest, held while a Scan request attests it, then published by moving the tag. A held digest never takes the tag's Current tag binding before the registry tag names it.
_Avoid_: promotion, tag gate, retag

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
