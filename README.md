# NSX DFW, Global Manager to Global Manager

Stage a distributed firewall from one NSX Global Manager onto another without turning the rules on.

License: GPL-3.0. Built and proved out for [essential.coach](https://essential.coach).
Full write-up: [Moving NSX DFW Between Global Managers Without Turning the Rules On](https://essential.coach/nsx-dfw-between-global-managers/)

VCF does not manage Global Manager lifecycle when federation spans two instances. This tool is the manual half: export, plan, apply. Policies are staged disabled. An API 200 is not realization proof.

## Run

```bash
python3 nsx_dfw_migrate.py --help
python3 nsx_dfw_migrate.py export --help
python3 nsx_dfw_migrate.py plan --help
python3 nsx_dfw_migrate.py apply --help
```

Apply does not write unless you pass `--commit`. Export, plan, and journal files are created so a second run cannot overwrite the last bundle. Mapped objects are reused. Network objects that are only dependencies are recorded, not recreated.

TLS verification is on. Do not point this at a UI export you cannot read.

## After apply

The policies are still disabled. Check realization and group membership on both sites before anyone enables a rule.
