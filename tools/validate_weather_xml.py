#!/usr/bin/env python3
"""Validation hors ligne du XML météo pour HsWeather.so.

Simule la machine à états du parseur SAX de CHsWeatherSvcXmlParser
(rétrogradé depuis tmp/fw/dec/HsWeather.so.bin) et vérifie qu'aucun
appel à SetMainDataByTag / SetWeeklyDataByTag ne se fait avec un objet
de données NULL — c'est ce qui faisait planter le Wave.

Les événements « characters » incluent les blancs : le parseur s'en sert
pour poser le contexte (parent), donc ils comptent dans la simulation.

Usage : python tools/validate_weather_xml.py [fichier.xml]
"""

import os
import sys
import xml.dom.minidom as minidom

TAGS = ["adc_database", "cities", "city", "citylist", "currentconditions", "day",
        "daycode", "daytime", "forecast", "hightemperature", "local", "location",
        "lowtemperature", "nighttime", "obsdate", "sunrise", "sunset", "temperature",
        "time", "units", "weathericon"]
IDX = {name: i for i, name in enumerate(TAGS)}
UNKNOWN = 21

# __HandleCharacters : table de saut retrouvée (base 0x1db38)
CH = {
    0: "root_reset",       # 0x1db4e
    1: "new_citylist",     # 0x1db7a -> CityList, parent=1
    2: "main_or_city",     # 0x1dbcc
    3: "new_loclist",      # 0x1db98 -> LocList, parent=3
    4: "ctx_cc",           # 0x1dbf8 -> parent=4
    5: "none",             # 0x1dc8c
    6: "main",             # 0x1dc36
    7: "ctx_daytime",      # 0x1dc58 -> parent=7 si parent=5
    8: "ctx_forecast",     # 0x1dc26 -> parent=8
    9: "weekly",           # 0x1dc6e
    10: "ctx_local",       # 0x1dbbc -> parent=10
    11: "none",
    12: "weekly",
    13: "ctx_nighttime",   # 0x1dc62 -> parent=13 si parent=5
    14: "main",            # obsdate
    15: "main",            # sunrise
    16: "main",            # sunset
    17: "main_cc",         # 0x1dc08 : temperature, parent=4 imposé
    18: "main_or_city",    # time
    19: "new_main",        # 0x1db5c -> ParsedData, parent=19
    20: "main",            # weathericon
}

# __HandleEndElement : table retrouvée (base 0x1d902)
END_PARENT = {
    0: UNKNOWN, 1: 0, 2: None, 3: 0, 4: 0, 5: 8, 6: None, 7: 5, 8: 0,
    9: None, 10: 0, 11: None, 12: None, 13: 5, 14: None, 15: None,
    16: None, 17: None, 18: None, 19: 0, 20: None,
}


class Sim:
    def __init__(self):
        self.state = 1
        self.parent = UNKNOWN
        self.current = UNKNOWN
        self.parsed = None       # NULL au départ : c'est la cause du crash
        self.mode = None
        self.flag = 1
        self.weekly = []
        self.errors = []
        self.fields = {}
        self.attrs = {}

    @staticmethod
    def tagname(i):
        return TAGS[i] if i < len(TAGS) and i >= 0 else "inconnu(%d)" % i

    def err(self, msg):
        self.errors.append(msg)

    def check_parent(self, expected):
        if self.parent != expected:
            self.state = 3
            self.err("CheckParent(%s) échoué (parent=%s) -> parsing interrompu" %
                     (TAGS[expected], self.tagname(self.parent)))
            return False
        return True

    def start(self, tag):
        self.current = IDX.get(tag, UNKNOWN)
        if self.state != 1:
            return
        if self.current == 2 and self.parent == 1:
            self.mode = "citylist"
        elif self.current == 5:
            if self.check_parent(8):
                self.weekly.append({"daycode": self.attrs.get("code")})
                self.parent = 5
        elif self.current == 11 and self.parent == 3:
            self.mode = "loclist"
            self.err("attention: <location> sous <citylist> = réponse LocList")

    def chars(self, text):
        if self.state != 1 or self.current == UNKNOWN:
            return
        t = self.current
        val = text.strip()
        action = CH.get(t, "none")

        if action == "root_reset":
            if self.flag == 1:
                self.parent = 0
                self.flag = 0
        elif action == "new_citylist":
            if self.check_parent(0):
                self.parsed = "CityList"
                self.parent = 1
        elif action == "new_loclist":
            if self.check_parent(0):
                self.parsed = "LocList"
                self.parent = 3
        elif action == "new_main":
            if self.check_parent(0):
                self.parsed = "Weather"
                self.parent = 19
        elif action == "ctx_cc":
            if self.check_parent(0):
                self.parent = 4
        elif action == "ctx_forecast":
            if self.check_parent(0):
                self.parent = 8
        elif action == "ctx_local":
            if self.check_parent(0):
                self.parent = 10
        elif action == "ctx_daytime":
            if self.parent == 5:
                self.parent = 7
        elif action == "ctx_nighttime":
            if self.parent == 5:
                self.parent = 13
        elif action in ("main", "main_cc", "main_or_city"):
            if action == "main_cc" and not self.check_parent(4):
                return
            if action == "main_or_city":
                if self.parent not in (10, 1):
                    return
            elif action == "main" and self.parent not in (4, 5, 7, 13):
                return
            if val:
                if self.parsed is None:
                    self.err("CRASH: SetMainDataByTag(%s) avec parsedData NULL" % TAGS[t])
                    return
                self.fields[TAGS[t]] = val
        elif action == "weekly":
            if self.parent not in (7, 13):
                return
            if self.parsed is None or not self.weekly:
                self.err("CRASH: SetWeeklyDataByTag(%s) sans donnée hebdo" % TAGS[t])
                return
            key = ("day" if self.parent == 7 else "night") + "_" + TAGS[t]
            if val:
                self.weekly[-1][key] = val
        self.current = UNKNOWN

    def end(self, tag):
        t = IDX.get(tag, UNKNOWN)
        if self.state == 1 and t < 21:
            np = END_PARENT[t]
            if np is not None:
                self.parent = np
        self.current = UNKNOWN

    def walk(self, node):
        for child in node.childNodes:
            if child.nodeType == child.ELEMENT_NODE:
                self.attrs = {a.name: a.value for a in child.attributes.values()}
                self.start(child.tagName)
                self.walk(child)
                self.end(child.tagName)
            elif child.nodeType == child.TEXT_NODE and child.data:
                self.chars(child.data)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        root, "store", "responses", "weather.xml")
    doc = minidom.parse(path)
    sim = Sim()
    sim.attrs = {}
    sim.start(doc.documentElement.tagName)
    sim.walk(doc.documentElement)
    print("Fichier      : %s" % path)
    print("parsedData   : %s" % sim.parsed)
    print("Champs lus   : %s" % sim.fields)
    print("Jours        : %d" % len(sim.weekly))
    for i, w in enumerate(sim.weekly):
        print("  jour %d     : %s" % (i + 1, w))
    if sim.errors:
        print("\nERREURS (%d) :" % len(sim.errors))
        for e in sim.errors:
            print("  - " + e)
        return 1
    print("\nOK : aucun appel sur objet NULL, machine a etats coherente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
