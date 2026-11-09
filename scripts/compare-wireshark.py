#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare what mmstracectl and Wireshark's MMS dissector (tshark) find in
captures.

Usage: compare-wireshark.py [--port N] [--mmstracectl BIN] CAPTURE...

For each capture it lists the MMS PDUs both see, as (kind, invoke ID,
service), and prints the differences: PDUs only one of them decodes, or that
they name differently. The comparison is on MMS structure (PDU kind, invoke
ID, and the confirmed service of a request), never on Wireshark's IEC 61850 labels, which are
heuristic. Initiate and conclude PDUs are not compared. PDUs of associations captured
midstream are counted and not compared: Wireshark needs the association to
dissect MMS, mmstracectl assumes the MMS presentation context. Exit status 1
when any capture differs or cannot be read, 2 on a usage error.
"""
import argparse, collections, json, subprocess, sys

# ISO 9506-2 ConfirmedServiceRequest/Response CHOICE numbers, as go-mms names them.
SERVICES = dict(enumerate(['Status', 'GetNameList', 'Identify', 'Rename', 'Read', 'Write', 'GetVariableAccessAttributes', 'DefineNamedVariable', 'DefineScatteredAccess', 'GetScatteredAccessAttributes', 'DeleteVariableAccess', 'DefineNamedVariableList', 'GetNamedVariableListAttributes', 'DeleteNamedVariableList', 'DefineNamedType', 'GetNamedTypeAttributes', 'DeleteNamedType', 'Input', 'Output', 'TakeControl', 'RelinquishControl', 'DefineSemaphore', 'DeleteSemaphore', 'ReportSemaphoreStatus', 'ReportPoolSemaphoreStatus', 'ReportSemaphoreEntryStatus', 'InitiateDownloadSequence', 'DownloadSegment', 'TerminateDownloadSequence', 'InitiateUploadSequence', 'UploadSegment', 'TerminateUploadSequence', 'RequestDomainDownload', 'RequestDomainUpload', 'LoadDomainContent', 'StoreDomainContent', 'DeleteDomain', 'GetDomainAttributes', 'CreateProgramInvocation', 'DeleteProgramInvocation', 'Start', 'Stop', 'Resume', 'Reset', 'Kill', 'GetProgramInvocationAttributes', 'ObtainFile', 'DefineEventCondition', 'DeleteEventCondition', 'GetEventConditionAttributes', 'ReportEventConditionStatus', 'AlterEventConditionMonitoring', 'TriggerEvent', 'DefineEventAction', 'DeleteEventAction', 'GetEventActionAttributes', 'ReportEventActionStatus', 'DefineEventEnrollment', 'DeleteEventEnrollment', 'AlterEventEnrollment', 'ReportEventEnrollmentStatus', 'GetEventEnrollmentAttributes', 'AcknowledgeEventNotification', 'GetAlarmSummary', 'GetAlarmEnrollmentSummary', 'ReadJournal', 'WriteJournal', 'InitializeJournal', 'ReportJournalStatus', 'CreateJournal', 'DeleteJournal', 'GetCapabilityList', 'FileOpen', 'FileRead', 'FileClose', 'FileRename', 'FileDelete', 'FileDirectory']))
KINDS = {"mms.confirmed_RequestPDU_element": "confirmed-request", "mms.confirmed_ResponsePDU_element": "confirmed-response",
         "mms.confirmed_ErrorPDU_element": "confirmed-error", "mms.rejectPDU_element": "reject",
         "mms.unconfirmed_PDU_element": "unconfirmed"}
STATUS_KIND = {"ok": "confirmed-response", "error": "confirmed-error", "reject": "reject"}


def walk(node):
    """Yield (key, value) of every nested field of a tshark JSON layer."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def wireshark(path, port):
    out = subprocess.run(["tshark", "-r", path, "-d", f"tcp.port=={port},tpkt", "-Y", "mms", "-T", "json", "--no-duplicate-keys"],
                         capture_output=True, text=True)
    events = collections.Counter()
    for pkt in json.loads(out.stdout or "[]"):
        layers = pkt["_source"]["layers"]
        mms = layers.get("mms")
        for pdu in (mms if isinstance(mms, list) else [mms]):
            if not isinstance(pdu, dict):
                continue
            for key, kind in KINDS.items():
                if key not in pdu:
                    continue
                for el in (pdu[key] if isinstance(pdu[key], list) else [pdu[key]]):
                    count(events, kind, el)
    return events


def count(events, kind, el):
    """Add one MMS PDU of a tshark JSON layer."""
    inv = svc = None
    for k, v in walk(el):
        if k in ("mms.invokeID", "mms.originalInvokeID") and inv is None:
            inv = int(v)
        if k in ("mms.confirmedServiceRequest", "mms.confirmedServiceResponse") and svc is None:
            svc = SERVICES.get(int(v), f"Service{v}")
    if kind == "unconfirmed":
        inv, svc = None, "InformationReport"
    if kind != "confirmed-request" and kind != "unconfirmed":
        svc = None  # answers are compared by kind and invoke ID
    events[(kind, inv, svc)] += 1


def run_json(binary, cmd, port, path):
    out = subprocess.run([binary, cmd, "--format", "json", "--port", str(port), path], capture_output=True, text=True)
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        raise RuntimeError((out.stderr or "no output").strip().splitlines()[-1])


def ours(path, port, binary):
    """The PDUs mmstracectl decodes, and how many of them are in associations
    captured midstream (Wireshark cannot dissect those without the
    association, so they are not compared)."""
    events = collections.Counter()
    midstream = {a["id"] for f in run_json(binary, "associations", port, path)["files"]
                 for a in f.get("associations") or [] if a["open"] == "midstream"}
    skipped = 0
    for cmd in ("transactions", "reports"):
        doc = run_json(binary, cmd, port, path)
        for f in doc["files"]:
            for t in f.get("transactions") or []:
                if t["association"] in midstream:
                    skipped += bool(t.get("request_frame")) + bool(t.get("response_frame"))
                    continue
                if t.get("request_frame"):
                    events[("confirmed-request", t["invoke_id"], t["service"] or None)] += 1
                kind = STATUS_KIND.get(t["status"])
                if t.get("response_frame") and kind is None and t["status"] == "orphan":
                    kind = "confirmed-response"
                if t.get("response_frame") and kind:
                    events[(kind, t["invoke_id"], None)] += 1
            for r in f.get("reports") or []:
                if r["association"] in midstream:
                    skipped += 1
                    continue
                events[("unconfirmed", None, "InformationReport")] += 1
    return events, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=102)
    ap.add_argument("--mmstracectl", default="mmstracectl")
    ap.add_argument("captures", nargs="+")
    a = ap.parse_args()
    differ = 0
    for path in a.captures:
        try:
            ws = wireshark(path, a.port)
            us, skipped = ours(path, a.port, a.mmstracectl)
        except RuntimeError as e:
            print(f"ERROR {path}: {e}")
            differ += 1
            continue
        only_ws, only_us = ws - us, us - ws
        # Wireshark dissects MMS only after it saw the association (the
        # presentation context): PDUs of associations captured midstream
        # are counted, not compared.
        note = f"; {skipped} more in associations captured midstream (not compared)" if skipped else ""
        if not only_ws and not only_us:
            print(f"SAME  {path}: {sum(ws.values())} PDUs{note}")
            continue
        differ += 1
        print(f"DIFF  {path}: Wireshark {sum(ws.values())}, mmstracectl {sum(us.values())} PDUs")
        for (k, i, s), n in sorted(only_ws.items(), key=str):
            print(f"      only Wireshark: {n} x {k} invoke {i} {s or ''}")
        for (k, i, s), n in sorted(only_us.items(), key=str):
            print(f"      only mmstracectl: {n} x {k} invoke {i} {s or ''}")
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    main()
