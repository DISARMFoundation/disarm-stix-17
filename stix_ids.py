# Reads STIX object IDs and saves from a DISARM STIX bundle and saves them in stix_ids.json
#
# The STIX generator uses stix_ids.json to ensure that objects retain the same STIX ID between updates.
#
# Author: VVX7
# License: GPL-3
import json

import pandas as pd
import openpyxl
from stix2 import (Bundle, AttackPattern, ThreatActor, IntrusionSet, Relationship, CustomObject, properties,
                   Malware, Tool, Campaign, Identity, MarkingDefinition, ExternalReference, StatementMarking,
                   GranularMarking, Location, MemoryStore, Filter)
from stix2.properties import (ReferenceProperty, ListProperty, StringProperty, TimestampProperty,
                   BooleanProperty, IntegerProperty)

import helpers
from objects import tactic, technique, matrix, bundle, relationship, identity, marking_definition
from helpers import xlsx, file


def write_json(data, filename):
    with open(filename, "w") as f:
        j = json.dumps(data, sort_keys=True, indent=2)
        f.write(j)


def get_identity(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "identity"))

    for i in a:
        data[i["name"]] = i["id"]

    return data


def get_marking_definition(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "marking-definition"))

    for i in a:
        data[i["name"]] = i["id"]

    return data


def get_attack_pattern(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "attack-pattern"))

    for i in a:
        data[i["external_references"][0]["external_id"]] = i["id"]

    for i in a:
        c = 0
        for v in a:
            if i["name"] == v["name"]:
                c += 1
            if c >= 2:
                print(i["name"])

    return data


def get_matrix(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "x-mitre-matrix"))

    for i in a:
        data[i["name"]] = i["id"]

    return data


def get_tactic(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "x-mitre-tactic"))

    for i in a:
        data[i["name"]] = i["id"]

    return data


def get_relationship(mem):
    data = dict()
    a = mem.query(Filter("type", "=", "relationship"))

    for i in a:
        data[i["id"]] = [i["source_ref"], i["target_ref"]]

    return data


def run():
    mem = MemoryStore()
    mem.load_from_file("DISARM.json")
    stix_ids = dict()

    stix_ids["identity"] = get_identity(mem)
    stix_ids["marking-definition"] = get_marking_definition(mem)
    stix_ids["attack-pattern"] = get_attack_pattern(mem)
    stix_ids["x-mitre-matrix"] = get_matrix(mem)
    stix_ids["x-mitre-tactic"] = get_tactic(mem)
    stix_ids["relationship"] = get_relationship(mem)

    write_json(stix_ids, "stix_ids.json")


if __name__ == "__main__":
    run()
