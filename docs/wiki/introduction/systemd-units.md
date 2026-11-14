# systemd units

On Linux hosts managed by [systemd](https://systemd.io/), the `systemd_units`
table exposes the units currently known to the service manager. Instead of
shelling out to `systemctl` and parsing its output, osquery talks to systemd
directly over D-Bus (the `org.freedesktop.systemd1` API), so the data matches
what the service manager itself reports.

The table is only available on Linux and requires access to the system D-Bus.

## Columns

Each row describes one unit returned by the systemd manager `ListUnits`
method. The most relevant columns are:

- `id`: the unique unit identifier, for example `sshd.service`.
- `type`: the unit type, derived from the suffix of `id` (for example
  `service`, `socket`, `timer`, `target`, `mount`, `device`).
- `load_state`: whether the unit definition was properly loaded, for example
  `loaded`, `not-found` or `masked`.
- `active_state`: the high-level activation state, for example `active`,
  `inactive` or `failed`.
- `sub_state`: the low-level activation state, whose values depend on the unit
  type, for example `running`, `dead` or `waiting`.
- `unit_file_state`: the enablement state of the unit file, for example
  `enabled`, `disabled` or `masked`.
- `fragment_path`: the unit file the unit was read from, if any.

See the full schema with `.schema systemd_units` inside the osquery shell, or
on the [schema page](https://osquery.io/schema).

## Filtering by unit type

The `type` column supports an equality predicate, so queries can restrict the
results to a single unit type:

```sql
SELECT id, load_state, active_state, sub_state
FROM systemd_units
WHERE type = 'service';
```

Other useful queries:

```sql
-- Units that entered the failed state
SELECT id, load_state, sub_state
FROM systemd_units
WHERE active_state = 'failed';

-- All timer units
SELECT id, active_state, sub_state
FROM systemd_units
WHERE type = 'timer';
```
