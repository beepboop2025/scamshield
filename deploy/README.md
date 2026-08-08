# ScamShield launchd deployment

The production bot and configured-channel monitor run as separate per-user
launchd services. Both execute `run_component.sh`, which applies the deployment
contract before Python starts:

- Guardian mode remains off unless BotFather grants both group capabilities.
- Raw IOC samples remain off.
- Palimpsest intake is enabled at `var/scamshield-inbox` for WATCH-or-higher
  assessments.
- The source-pseudonym HMAC key comes from macOS Keychain service
  `com.scamshield.pseudonym-key`; it is never stored in the repository or plist.
- Both processes share the SQLite WAL database at `scamshield.db`.

Install the bot plist only after tests and Telegram `getMe`/webhook preflight
pass. Install the monitor plist only after `python login.py` has created
`scamshield_monitor.session` for the dedicated monitoring account.

Useful checks:

```bash
launchctl print gui/$(id -u)/com.scamshield.bot
launchctl print gui/$(id -u)/com.scamshield.monitor
tail -n 100 ~/Library/Logs/ScamShield/bot.err.log
tail -n 100 ~/Library/Logs/ScamShield/monitor.err.log
```
