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

**Scan request**:
An expressed intent to scan a specific container image, whether discovered automatically or initiated as a rescan.
_Avoid_: queue task, worker job
