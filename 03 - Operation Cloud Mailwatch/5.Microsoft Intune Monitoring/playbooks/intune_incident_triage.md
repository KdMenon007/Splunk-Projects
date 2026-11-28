# Microsoft Intune Incident Triage & Hardening Playbook

## 1. Validate Admin Sign-In & Device Context
* Inspect Entra ID sign-in logs for `appDisplayName=*Intune*` or `"Microsoft Intune portal extension"`.
* Check `deviceDetail.displayName`, `deviceDetail.isManaged`, `deviceDetail.isCompliant`, `deviceDetail.trustType`, `ipAddress`, location, and time.

## 2. Investigate High-Impact Intune Actions
* **Remote Wipe (`wipe ManagedDevice`):** Extract `deviceid` and `actor.userPrincipalName`, then pivot to device/Entra records to identify hostname, hardware ID, OS, and user.
* **Platform Scripts (`*DeviceManagementScript*`):** Track `CreateDeviceManagementScript`, `AssignDeviceManagementScript`, and `DeleteDeviceManagementScript` (including `resourceId` and target IDs such as `adadadad-808e-44e2-905a-0b7873a8a531` for All Devices). Note that script deletion can indicate anti-forensic cleanup after execution.
* **App Deployment (`*MobileApp*`):** Review who deployed the package, which targets received it, and whether unsigned or malicious `.intunewin`/`.pkg`/`.dmg` packages were pushed.

## 3. Correlate Endpoint & Forensic Artifacts
* On Windows endpoints, trace `Microsoft.Management.Services.IntuneWindowsAgent.exe` -> `AgentExecutor.exe` -> `powershell.exe` via Sysmon event 1 or Security event 4688.
* Check `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log` for execution timestamps, duration, output, and errors.

## 4. Contain & Harden
* Revoke active sessions/tokens and reset credentials for compromised admin accounts.
* Enforce Conditional Access, Identity Protection, PIM, hardware MFA/passkeys, custom RBAC roles, Scope Tags, and Multi-Admin Approval.
