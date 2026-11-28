# SharePoint Online Compromise Triage Playbook (v2)

## Phase 1: Authentication & Baseline Context
* Check Entra ID sign-in logs (`azure:aad:signin`) for source IP, location (`location.city`), device/app (`appDisplayName`), timing, and anomalies before or alongside SharePoint events.
* Compare activity volume and behavior against the user's normal role and baseline rather than relying solely on static counts.

## Phase 2: Discovery, Downloads & File Changes
* Hunt `FileAccessed` for sensitive filename pivots (`*password*`, `*credential*`, `*secret*`, `*contract*`, `*finance*`) as pivots rather than final verdicts.
* Analyze `FileDownloaded` totals, `span=1h` spikes, and folder-level downloads (`SourceRelativeUrl`, `values(SourceFileName)`) to spot bulk or folder exfiltration.
* Review `FileUploaded`, `FileCreated`, `FileModified`, and `FileDeleted`/`FileRecycled` in chronological order for phishing staging, existing file tampering, or cleanup.

## Phase 3: Sharing, Link Usage & Client Applications
* Track `AddedToSecureLink`, `AnonymousLinkCreated`, `SharingSet`, `SecureLinkUsed`, and `AnonymousLinkUsed` together to prove whether shared links were actually accessed.
* Inspect `ApplicationDisplayName`, `UserAgent`, and per-user application diversity (`dc(ApplicationDisplayName)`) for unexpected sync clients or tools such as Rclone.
* Pivot on `ObjectId` across upload, sharing, and access events to build a complete timeline of a suspicious or phishing file.

## Phase 4: Containment & Remediation
* Revoke external sharing links, remove unauthorized guest access, and reset credentials / revoke active tokens for compromised identities.
* Investigate recipients who opened or downloaded shared/phishing files and verify whether sensitive data was exfiltrated.
