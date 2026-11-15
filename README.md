# Service Checker

A small Windows tool for Minecraft screenshares. It checks the services and settings that record what happened on a PC, shows which ones are stopped, disabled, restarted or frozen, and can turn them back on.

Players turn these off so nothing gets recorded. This tool shows you that in one window, saves the proof, and then lets you fix it so the rest of the SS can keep going.

## Download

    https://github.com/aaa1243/service-checker/releases/latest/download/ServiceChecker.exe

Windows shows an "unknown publisher" warning because the exe is not signed. Click Run.

## Run it without downloading

From an admin CMD or PowerShell on the player's PC:

    powershell -ExecutionPolicy Bypass -Command "iex (irm https://raw.githubusercontent.com/aaa1243/service-checker/main/ServiceChecker.ps1)"

That opens the same window as the exe. If you want plain text in the console instead:

    powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm https://raw.githubusercontent.com/aaa1243/service-checker/main/ServiceChecker.ps1))) -NoGui"

A one-liner like this runs whatever is at that link at that moment, so only ever use the link to this repo.

## How to use it

1. Run `ServiceChecker.exe` on the player's PC and accept the admin prompt.
2. Read the RESULT column. Click a row to see what the result means.
3. Take your screenshot. A report of what it found is already saved in `C:\SSTools\ServiceChecker`.
4. If you want the services back on, click **Select problems**, then **Fix selected**.

## What it checks

| Service | What it records |
|---|---|
| SysMain | Prefetch files |
| DPS | Program names and times, kept in memory |
| PcaSvc | Program launches (PCA) |
| EventLog | The Windows event logs |
| Schedule | Scheduled tasks |
| bam | The BAM driver, what each user ran |
| Dnscache | The DNS cache |
| PlugPlay | Devices and USB drives |
| Appinfo | Programs run as admin |
| DcomLaunch | Starts COM programs |
| BFE | Base Filtering Engine, firewall and network rules |
| DiagTrack, DusmSvc, WSearch, CDPSvc, CDPUserSvc, SSDPSRV | Extra traces. These are shown as notes because privacy tools often turn them off |

Settings it checks:

| Setting | What it means when it is off |
|---|---|
| `EnablePrefetcher` | Prefetch records nothing |
| `MiniNt` key | Windows stops writing event logs |
| `DisablePCA` policy | PcaSvc stops recording launches |
| `DisableCMD` policy | Command Prompt is blocked |
| PowerShell script logging policy | PowerShell commands are not logged |
| `Start_TrackDocs` | Recent items and jump lists are not recorded |
| Activity history policy | The Activities cache stops recording |
| USN journal on the Windows drive | Reported only |
| Prefetch folder | Reported only: file count, read-only or hidden .pf files, and .pf files with identical content (one copied over another) |

The log box also shows the latest journal delete (3079), log clears (104, 1102), time change (4616), shutdown request (1074) and Event Log start (6005), marked if they happened since boot, plus every drive and its file system.

## What the results mean

| Result | Meaning |
|---|---|
| OK | Normal |
| DISABLED | Start type is Disabled. Windows does not do that by itself |
| STOPPED | It should run the whole session and is not running |
| RESTARTED | Its process started long after boot, so it was stopped or restarted this session |
| FROZEN | It shows as running but every thread is suspended, so it records nothing |
| MISSING / CHANGED / PRESENT / SET | A setting is not what Windows ships with |
| TAMPERED / COPIED FILES | Prefetch files were made read-only or hidden, or copied over each other |

The box at the bottom also lists every start type change and stop for these services that Windows logged since boot, with the time and the account that did it when the log has it.

## What Fix does

- Sets the service back to its normal Windows start type and starts it.
- Sets `EnablePrefetcher` back to 3, removes the `MiniNt` key, removes the policy values listed above and sets `Start_TrackDocs` back to 1.
- Saves a `before_fix` report first and an `after_fix` report after, so you have both for the ban log.

It never stops, disables or deletes a service. It does not recreate a deleted USN journal and it does not unfreeze suspended threads. Those are reported only.

## Good to know

- Turning a service back on does not bring back what was lost. If DPS was stopped, the names it held in memory are gone. The point of fixing is so the rest of the SS gets recorded.
- Screenshot before you fix. A disabled service is evidence, and after the fix the window shows it as OK.
- Some services (Dnscache is one) are locked by Windows. If the tool can only change the registry value, it says so and the change applies after a reboot.
- A RESTARTED result is a warning, not proof. Windows restarts services itself sometimes, for example after an update.
- The rule on what is bannable is your server's. This tool only shows the state.

## Run from source

    powershell -ExecutionPolicy Bypass -File ServiceChecker.ps1

Without the window, for testing:

    powershell -ExecutionPolicy Bypass -File ServiceChecker.ps1 -NoGui
    powershell -ExecutionPolicy Bypass -File ServiceChecker.ps1 -NoGui -Fix

To add or remove a service, edit the `$ServiceList` block at the top of the script.

## Credits

The idea of a one-line service check comes from the SS community. The service and setting lists were compared against [lilith-ps](https://github.com/praiselily/lilith-ps) by praiselily and [RBW-SS](https://github.com/quickpots/RBW-SS) by QuickPots so nothing they check is missing here. The code in this repo is written from scratch.

## License

MIT
