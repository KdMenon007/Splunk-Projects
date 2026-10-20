# Challenge Investigation — `svcupdate` on `THM-SHR-SRV`

## Objective
Trace the lateral-movement path associated with a suspicious service installation on `THM-SHR-SRV` using the supplied Splunk evidence.

## Observed evidence

- **Destination:** `THM-SHR-SRV`
- **Service binary:** `%SystemRoot%\\svcupdate.exe`
- **Administrative share account:** `ryan.chen`
- **Source IP:** `10.5.50.15`
- **Source host identified from the machine-account event:** `THM-HR-WS` (`THM-HR-WS$`)
- **First observed command:** `cmd /c "hostname & whoami & ipconfig"`

## Reconstructed chain

```text
THM-HR-WS (10.5.50.15)
        |
        | SMB / ADMIN$ using ryan.chen
        v
THM-SHR-SRV
        |
        +--> Event 5140: administrative share access
        +--> Event 7045: svcupdate service installed
        +--> Sysmon Event 1: remote command execution / discovery
```

## Splunk queries

### Service installation

```spl
index=challenge EventCode=7045 host=THM-SHR-SRV
| table _time, service_path
| sort _time
```

### Administrative share access

```spl
index=challenge EventCode=5140 host=THM-SHR-SRV
| table _time, user, Source_Address
| sort _time
```

### Command execution

```spl
index=challenge EventCode=1 host=THM-SHR-SRV
| table _time, CommandLine
| sort _time
```

### Map source IP to source machine account

```spl
index=challenge EventCode=4624 Source_Network_Address=10.5.50.15 user=*$
| stats count by user, Source_Network_Address
| sort -count
```

### Review account names observed in logons from the source IP

```spl
index=challenge EventCode=4624 Source_Network_Address=10.5.50.15
| table _time, user, Account_Name, Source_Network_Address, Logon_ID
| sort _time
```

## Interpretation and limitations

The service-installation, share-access, and process-creation events collectively support an SMB-based remote execution chain from `THM-HR-WS` to `THM-SHR-SRV`. Event 7045 alone does not prove PsExec was used: `svcupdate.exe` is a suspicious service name/path in this context, but attribution to a particular tool requires additional corroboration. Confirm the actual field names and event coverage in the target Splunk deployment before reusing these searches.
