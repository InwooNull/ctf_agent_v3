"""Dummy category -> lane mapping."""

LANES = {
    "crypto": "crypto_lane",
    "pwn": "pwn_lane",
    "web": "web_lane",
    "rev": "rev_lane",
    "forensics": "forensics_lane",
    "ai": "ai_lane",
    "misc": "generic_lane",
}


def route(category):
    return LANES.get(category, "generic_lane")
