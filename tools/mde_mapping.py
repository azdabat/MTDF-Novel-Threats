#!/usr/bin/env python3
"""
mde_mapping.py  —  shared Sysmon -> Defender(MDE) mapping core.

Both sysmon_to_mde.py (live VM export) and mordor_to_mde.py (OTRF datasets)
feed events into convert_events() here, so the schema mapping lives in ONE place.

Input event shape (normalised by each caller):
    { "EventId": int, "Computer": str, "TimeCreated": str|None,
      "RecordId": any, "EventData": { <sysmon field> : value, ... } }

convert_events() does three things the per-event mappers can't:
  1. Deterministic DeviceId per host (so cross-table joins resolve).
  2. ProcessGuid enrichment — fills InitiatingProcessSHA256 / CompanyName etc.
     that Sysmon only records on the acting process's OWN EID1, not on the
     registry/file/network event. This is what makes writer-reputation logic
     in composite rules actually testable.
  3. Registry hive normalisation to MDE long form (HKLM -> HKEY_LOCAL_MACHINE).
"""
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone


# ---------- helpers ----------

def leaf(path):
    if not path:
        return path
    return path.replace("/", "\\").split("\\")[-1]


def split_user(user):
    if not user:
        return (None, None)
    if "\\" in user:
        dom, name = user.split("\\", 1)
        return (dom, name)
    return (None, user)


def parse_hashes(s):
    out = {}
    if not s:
        return out
    for part in s.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().upper()] = v.strip()
    return out


def to_iso(utctime, fallback=None):
    if utctime:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(utctime, fmt).replace(tzinfo=timezone.utc)
                return dt.isoformat().replace("+00:00", "Z")
            except ValueError:
                continue
    if fallback:
        try:
            dt = datetime.fromisoformat(str(fallback).replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            return fallback
    return None


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def derive_device_id(name):
    """Stable 40-hex DeviceId per host so joins on DeviceId resolve in fixtures."""
    if not name:
        name = "unknown"
    return hashlib.sha1(str(name).strip().lower().encode()).hexdigest()


_HIVE = {"HKLM": "HKEY_LOCAL_MACHINE", "HKU": "HKEY_USERS",
         "HKCR": "HKEY_CLASSES_ROOT", "HKCU": "HKEY_CURRENT_USER"}


def normalize_hive(path):
    if not path:
        return path
    up = path.upper()
    for short, long in _HIVE.items():
        if up.startswith(short + "\\"):
            return long + path[len(short):]
    return path


def prune(row):
    return {k: v for k, v in row.items() if v is not None and v != ""}


# ---------- per-EventID mappers (return (table, row)) ----------

def _base_initiating(d):
    dom, name = split_user(d.get("User"))
    return {
        "InitiatingProcessFileName": leaf(d.get("Image")),
        "InitiatingProcessFolderPath": d.get("Image"),
        "InitiatingProcessId": as_int(d.get("ProcessId")),
        "InitiatingProcessAccountDomain": dom,
        "InitiatingProcessAccountName": name,
    }


def map_process(ts, dev, d):
    h = parse_hashes(d.get("Hashes"))
    adom, aname = split_user(d.get("User"))
    pdom, pname = split_user(d.get("ParentUser"))
    return ("DeviceProcessEvents", {
        "Timestamp": ts, "DeviceName": dev, "ActionType": "ProcessCreated",
        "FileName": leaf(d.get("Image")), "FolderPath": d.get("Image"),
        "ProcessId": as_int(d.get("ProcessId")),
        "ProcessCommandLine": d.get("CommandLine"),
        "ProcessCreationTime": ts,
        "ProcessIntegrityLevel": d.get("IntegrityLevel"),
        "AccountDomain": adom, "AccountName": aname,
        "SHA256": h.get("SHA256"), "SHA1": h.get("SHA1"), "MD5": h.get("MD5"),
        "ProcessVersionInfoCompanyName": d.get("Company"),
        "ProcessVersionInfoProductName": d.get("Product"),
        "ProcessVersionInfoOriginalFileName": d.get("OriginalFileName"),
        "ProcessVersionInfoFileDescription": d.get("Description"),
        "InitiatingProcessFileName": leaf(d.get("ParentImage")),
        "InitiatingProcessFolderPath": d.get("ParentImage"),
        "InitiatingProcessId": as_int(d.get("ParentProcessId")),
        "InitiatingProcessCommandLine": d.get("ParentCommandLine"),
        "InitiatingProcessAccountDomain": pdom, "InitiatingProcessAccountName": pname,
    })


def map_network(ts, dev, d):
    # Sysmon EID 3: Source* is the side that INITIATED the connection, Destination* the side that
    # accepted it. For an inbound connection (Initiated=false) the local endpoint is therefore the
    # Destination, so Local/Remote must be swapped relative to an outbound one.
    initiated = str(d.get("Initiated", "")).lower() == "true"
    local, remote = ("Source", "Destination") if initiated else ("Destination", "Source")
    row = {
        "Timestamp": ts, "DeviceName": dev,
        "ActionType": "ConnectionSuccess" if initiated else "InboundConnectionAccepted",
        "Protocol": d.get("Protocol"),
        "LocalIP": d.get(f"{local}Ip"), "LocalPort": as_int(d.get(f"{local}Port")),
        "RemoteIP": d.get(f"{remote}Ip"), "RemotePort": as_int(d.get(f"{remote}Port")),
        "RemoteUrl": d.get(f"{remote}Hostname"),
    }
    row.update(_base_initiating(d))
    return ("DeviceNetworkEvents", row)


def map_imageload(ts, dev, d):
    h = parse_hashes(d.get("Hashes"))
    row = {
        "Timestamp": ts, "DeviceName": dev, "ActionType": "ImageLoaded",
        "FileName": leaf(d.get("ImageLoaded")), "FolderPath": d.get("ImageLoaded"),
        "SHA256": h.get("SHA256"), "SHA1": h.get("SHA1"), "MD5": h.get("MD5"),
    }
    row.update(_base_initiating(d))
    return ("DeviceImageLoadEvents", row)


def _file(ts, dev, d, action):
    h = parse_hashes(d.get("Hashes"))
    row = {
        "Timestamp": ts, "DeviceName": dev, "ActionType": action,
        "FileName": leaf(d.get("TargetFilename")), "FolderPath": d.get("TargetFilename"),
        "SHA256": h.get("SHA256"),
    }
    row.update(_base_initiating(d))
    return ("DeviceFileEvents", row)


def map_filecreate(ts, dev, d):
    return _file(ts, dev, d, "FileCreated")


def map_filedelete(ts, dev, d):
    return _file(ts, dev, d, "FileDeleted")


def _registry(ts, dev, d, action):
    target = normalize_hive(d.get("TargetObject") or "")
    key, value = target, None
    if action == "RegistryValueSet" and "\\" in target:
        key, value = target.rsplit("\\", 1)
    row = {
        "Timestamp": ts, "DeviceName": dev, "ActionType": action,
        "RegistryKey": key, "RegistryValueName": value,
        "RegistryValueData": d.get("Details"),
    }
    row.update(_base_initiating(d))
    return ("DeviceRegistryEvents", row)


def map_reg_add_del(ts, dev, d):
    et = (d.get("EventType") or "").lower()
    return _registry(ts, dev, d, "RegistryKeyDeleted" if "delete" in et else "RegistryKeyCreated")


def map_reg_set(ts, dev, d):
    return _registry(ts, dev, d, "RegistryValueSet")


def map_reg_rename(ts, dev, d):
    return _registry(ts, dev, d, "RegistryKeyRenamed")


def _device_event(ts, dev, d, action, extra):
    row = {
        "Timestamp": ts, "DeviceName": dev, "ActionType": action,
        "InitiatingProcessFileName": leaf(d.get("SourceImage") or d.get("Image")),
        "InitiatingProcessFolderPath": d.get("SourceImage") or d.get("Image"),
        "InitiatingProcessId": as_int(d.get("SourceProcessId") or d.get("ProcessId")),
        "FileName": leaf(d.get("TargetImage")), "FolderPath": d.get("TargetImage"),
        "AdditionalFields": json.dumps({k: d.get(k) for k in extra if d.get(k) is not None}) if extra else None,
    }
    sdom, sname = split_user(d.get("SourceUser") or d.get("User"))
    row["InitiatingProcessAccountDomain"] = sdom
    row["InitiatingProcessAccountName"] = sname
    return ("DeviceEvents", row)


def map_createremotethread(ts, dev, d):
    return _device_event(ts, dev, d, "CreateRemoteThreadApiCall",
                         ["StartAddress", "StartModule", "StartFunction", "TargetProcessId"])


def map_processaccess(ts, dev, d):
    return _device_event(ts, dev, d, "OpenProcessApiCall",
                         ["GrantedAccess", "CallTrace", "TargetProcessId"])


def map_dns(ts, dev, d):
    row = {
        "Timestamp": ts, "DeviceName": dev, "ActionType": "DnsQueryResponse",
        "AdditionalFields": json.dumps({"QueryName": d.get("QueryName"),
                                        "QueryStatus": d.get("QueryStatus"),
                                        "QueryResults": d.get("QueryResults")}),
    }
    row.update(_base_initiating(d))
    return ("DeviceEvents", row)


def map_wmi_filter(ts, dev, d):
    return _device_event(ts, dev, d, "WmiEventFilterCreated",
                         ["Operation", "EventNamespace", "Name", "Query"])


def map_wmi_consumer(ts, dev, d):
    return _device_event(ts, dev, d, "WmiConsumerCreated",
                         ["Operation", "Name", "Type", "Destination"])


def map_wmi_binding(ts, dev, d):
    return _device_event(ts, dev, d, "WmiBindEventFilterToConsumer",
                         ["Operation", "Consumer", "Filter"])


DISPATCH = {
    1: map_process, 3: map_network, 7: map_imageload, 8: map_createremotethread,
    10: map_processaccess, 11: map_filecreate, 12: map_reg_add_del, 13: map_reg_set,
    14: map_reg_rename, 19: map_wmi_filter, 20: map_wmi_consumer, 21: map_wmi_binding,
    22: map_dns, 23: map_filedelete, 26: map_filedelete,
}

# EIDs with no faithful MDE column — land in DeviceEvents as approximations.
APPROX_EIDS = {8, 10, 19, 20, 21, 22}


# ---------- enrichment ----------

def _guid(d, *keys):
    for k in keys:
        if d.get(k):
            return d.get(k)
    return None


def _build_guid_index(events):
    """ProcessGuid -> acting process identity, from every EID1."""
    idx = {}
    for ev in events:
        if ev.get("EventId") != 1:
            continue
        d = ev.get("EventData") or {}
        g = _guid(d, "ProcessGuid", "ProcessGUID")
        if not g:
            continue
        h = parse_hashes(d.get("Hashes"))
        idx[g] = {
            "SHA256": h.get("SHA256"), "SHA1": h.get("SHA1"), "MD5": h.get("MD5"),
            "Company": d.get("Company"), "Product": d.get("Product"),
            "OriginalFileName": d.get("OriginalFileName"), "Description": d.get("Description"),
            "CommandLine": d.get("CommandLine"), "ParentImage": leaf(d.get("ParentImage")),
            "IntegrityLevel": d.get("IntegrityLevel"),
        }
    return idx


def _enrich(row, guid, idx):
    e = idx.get(guid)
    if not e:
        return
    for src, dst in (("SHA256", "InitiatingProcessSHA256"),
                     ("SHA1", "InitiatingProcessSHA1"),
                     ("MD5", "InitiatingProcessMD5"),
                     ("Company", "InitiatingProcessVersionInfoCompanyName"),
                     ("Product", "InitiatingProcessVersionInfoProductName"),
                     ("OriginalFileName", "InitiatingProcessVersionInfoOriginalFileName"),
                     ("Description", "InitiatingProcessVersionInfoFileDescription"),
                     ("CommandLine", "InitiatingProcessCommandLine"),
                     ("ParentImage", "InitiatingProcessParentFileName"),
                     ("IntegrityLevel", "InitiatingProcessIntegrityLevel")):
        if e.get(src) and not row.get(dst):
            row[dst] = e[src]


# ---------- driver ----------

def convert_events(events, provenance=False, device_override=None, normalize_registry=True):
    """events -> (tables: {table: [rows]}, skipped: {eid: count})."""
    guid_index = _build_guid_index(events)
    tables = defaultdict(list)
    skipped = defaultdict(int)

    for ev in events:
        eid = ev.get("EventId")
        d = ev.get("EventData") or {}
        dev = device_override or ev.get("Computer")
        ts = to_iso(d.get("UtcTime"), ev.get("TimeCreated"))
        fn = DISPATCH.get(eid)
        if not fn:
            skipped[eid] += 1
            continue
        table, row = fn(ts, dev, d)

        # DeviceId + ReportId so cross-table joins resolve
        row["DeviceId"] = derive_device_id(dev)
        if ev.get("RecordId") is not None:
            row["ReportId"] = as_int(ev.get("RecordId"))

        # ProcessGuid enrichment of InitiatingProcess* (writer reputation)
        if table == "DeviceProcessEvents":
            _enrich(row, _guid(d, "ParentProcessGuid", "ParentProcessGUID"), guid_index)
        else:
            _enrich(row, _guid(d, "SourceProcessGUID", "SourceProcessGuid",
                                  "ProcessGuid", "ProcessGUID"), guid_index)

        if provenance:
            row["_SysmonEventId"] = eid
            row["_SysmonRecordId"] = ev.get("RecordId")
            row["_Approx"] = eid in APPROX_EIDS

        if table == "DeviceNetworkEvents":
            row["_guid"] = _guid(d, "ProcessGuid", "ProcessGUID")
        tables[table].append(prune(row))

    _link_dns(events, tables.get("DeviceNetworkEvents", []))
    return tables, skipped


_IP_RX = re.compile(r"(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})")


def _link_dns(events, net_rows):
    """Defender's RemoteUrl is the name the process asked for; Sysmon EID 3 only has reverse DNS.
    Recover the real name from the same process's own EID 22 query whose answer holds that IP."""
    answers = {}
    for ev in events:
        if ev.get("EventId") != 22:
            continue
        d = ev.get("EventData") or {}
        name = d.get("QueryName")
        g = _guid(d, "ProcessGuid", "ProcessGUID")
        if not name or not g:
            continue
        for ip in _IP_RX.findall(str(d.get("QueryResults") or "")):
            answers[(g, ip)] = name
    for row in net_rows:
        g = row.pop("_guid", None)
        name = answers.get((g, row.get("RemoteIP")))
        if name:
            row["RemoteUrl"] = name
