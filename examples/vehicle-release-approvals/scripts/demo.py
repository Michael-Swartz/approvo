#!/usr/bin/env python3
"""End-to-end walkthrough against the running example API.

Start the stack first:

    docker compose up -d          # MongoDB
    uvicorn app.main:app --reload # in another terminal, from this directory

Then run this script from this directory:

    python scripts/demo.py

It creates a vehicle software release request, has two approvers (one
safety-engineer, one qa — the policy requires both roles) approve it,
polls the authoritative status, lists releases, and publishes + verifies
a checkpoint over the ledger.
"""

from __future__ import annotations

import sys

import httpx

BASE_URL = "http://localhost:8000"


def main() -> None:
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        identities = client.get("/identities").raise_for_status().json()
        print("known approvers:", identities)

        created = client.post(
            "/releases",
            json={
                "subject": {
                    "ecu": "brake-controller",
                    "artifact_digest": "sha256:" + "ab" * 32,
                    "version": "3.2.1",
                    "vehicle_platform": "model-x",
                },
                "requested_by": "user:sam",
                "approval_window_hours": 168,
            },
        ).raise_for_status().json()
        request_id = created["request_id"]
        print("created release request:", request_id)

        # Safety engineer approves.
        status = client.post(
            f"/releases/{request_id}/decisions",
            json={
                "approver_id": "user:priya",
                "verdict": "approve",
                "comment": "brake HIL suite green",
            },
        ).raise_for_status().json()
        print("status after 1st approval:", status["status"], status["reasons"])

        # QA approves — threshold (2) and required distinct roles are now met.
        status = client.post(
            f"/releases/{request_id}/decisions",
            json={
                "approver_id": "user:noah",
                "verdict": "approve",
                "comment": "regression suite green",
            },
        ).raise_for_status().json()
        print("status after 2nd approval:", status["status"], status["reasons"])

        # Re-derived, authoritative status — this is what a deploy gate calls.
        gate = client.get(f"/releases/{request_id}").raise_for_status().json()
        assert gate["status"] == "approved", gate
        print("gate check passed:", gate["status"])

        listing = client.get("/releases", params={"status": "approved"}).raise_for_status().json()
        print("approved releases:", [item["request_id"] for item in listing["items"]])

        checkpoint = client.post("/checkpoint").raise_for_status().json()
        print("published checkpoint over", checkpoint["tree_size"], "ledger entries")

        report = client.get("/verify").raise_for_status().json()
        print("ledger verified:", report["ok"], "-", len(report["checks"]), "checks passed")
        if not report["ok"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
