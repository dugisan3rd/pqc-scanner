#!/usr/bin/env python3

''' Generate a consistent timestamp and random suffix '''

# ---------- IMPORT PACKAGES ----------
import time, random, string

# ---------- GENERATE TIMESTAMP ----------
def get_timestamp() -> float:
    return time.time()

# ---------- GENERATE RANDOM SUFFIX ----------
def get_random_suffix(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))