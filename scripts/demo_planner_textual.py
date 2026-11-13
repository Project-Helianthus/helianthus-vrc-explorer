#!/usr/bin/env python3
from __future__ import annotations

import os

from helianthus_vrc_explorer.scanner.planner_model import PlannerGroup
from helianthus_vrc_explorer.ui.planner_textual import run_textual_scan_plan


def main() -> int:
    verbose = os.environ.get("HELIA_DEMO_VERBOSE", "").strip() == "1"
    groups = [
        PlannerGroup(
            group=0x00,
            name="Regulator Parameters",
            descriptor=3.0,
            known=True,
            ii_max=None,
            rr_max=0x00FF,
            present_instances=(0x00,),
        ),
        PlannerGroup(
            group=0x01,
            name="Hot Water Circuit",
            descriptor=3.0,
            known=True,
            ii_max=None,
            rr_max=0x001F,
            present_instances=(0x00,),
        ),
        PlannerGroup(
            group=0x02,
            name="Heating Circuits",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x0021,
            present_instances=(0x00, 0x02, 0x03, 0x04),
        ),
        PlannerGroup(
            group=0x03,
            name="Zones",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x002F,
            present_instances=(0x00, 0x01),
        ),
        PlannerGroup(
            group=0x06,
            name="Unknown Group",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x0030,
            present_instances=tuple(range(0x00, 0x0A + 1)),
        ),
        PlannerGroup(
            group=0x07,
            name="Unknown Group",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x0030,
            present_instances=tuple(range(0x00, 0x0A + 1)),
        ),
        PlannerGroup(
            group=0x09,
            name="RoomSensors",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x002F,
            present_instances=(0x01,),
        ),
        PlannerGroup(
            group=0x0A,
            name="RoomState",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x003F,
            present_instances=(0x01,),
        ),
    ]

    plan = run_textual_scan_plan(
        groups,
        request_rate_rps=4.0,
        default_plan=None,
        default_preset="recommended",
    )
    if plan is None:
        if verbose:
            print("cancelled")
        return 1
    if verbose:
        print(f"saved {len(plan)} groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
