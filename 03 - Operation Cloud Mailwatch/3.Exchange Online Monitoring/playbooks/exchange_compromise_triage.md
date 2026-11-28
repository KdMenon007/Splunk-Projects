# Exchange Online Triage Playbook

1. Review sign-in logs (`One Outlook Web`) for unfamiliar cities or source IPs.
2. Check `New-InboxRule` and `Set-Mailbox` for external forwarding or `DeleteMessage=True` concealment.
3. Correlate `Send` events and `o365:reporting:messagetrace` to map phishing recipients and replies.
4. Revoke sessions, reset passwords, remove unauthorized rules/forwarding, and investigate affected users.
