#!/usr/bin/env python3
import os
import re
import sys
import shutil
import tempfile
import subprocess

# Directory this script lives in
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def find_tool(name, fallback):
    """Locate `name` on PATH or fall back to `fallback` in the script directory."""
    path = shutil.which(name)
    if path:
        return path
    fallback_path = os.path.join(SCRIPT_DIR, fallback)
    if os.path.isfile(fallback_path):
        return fallback_path
    print(f"Error: neither '{name}' nor '{fallback}' was found.", file=sys.stderr)
    sys.exit(1)

# Locate assembler and objcopy
AS_CMD      = find_tool("as",      "xenon-as.exe")
OBJCOPY_CMD = find_tool("objcopy", "xenon-objcopy.exe")
MACROS_FILE = os.path.join(SCRIPT_DIR, "macros.S")

# Regex to capture MAKEPATCH blocks
PATCH_RE = re.compile(
    r"MAKEPATCH\s+0x([0-9A-Fa-f]+)"       # address
    r"[\s\S]*?"                            # anything until
    r"0:\s*\n([\s\S]*?)9:",             # between labels
    re.DOTALL
)

def parse_patches(text):
    patches = {}
    for m in PATCH_RE.finditer(text):
        addr = int(m.group(1), 16)
        insns = [ln.strip() for ln in m.group(2).splitlines() if ln.strip()]
        patches[addr] = insns
    return patches


def assemble_with_macros(addr, insns):
    # Ensure include path uses forward slashes
    inc_path = MACROS_FILE.replace('\\', '/')

    # Create assembly content with macros
    asm_lines = [
        f'.include "{inc_path}"',
        f"MAKEPATCH 0x{addr:X}",
        "0:", *insns, "9:"
    ]
    asm_content = "\n".join(asm_lines) + "\n"

    # Write to temp .S file
    with tempfile.NamedTemporaryFile(suffix=".S", delete=False) as tmp:
        tmp.write(asm_content.encode())
        asm_path = tmp.name

    obj_path = asm_path + ".o"
    bin_path = asm_path + ".bin"

    # Assemble (xenon-as with -mregnames)
    try:
        subprocess.run(
            [AS_CMD, "-mregnames", "-o", obj_path, asm_path],
            check=True, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        print(f"Error assembling patch @0x{addr:X}:", file=sys.stderr)
        print(e.stderr.decode(), file=sys.stderr)
        print("Assembly source:\n" + asm_content, file=sys.stderr)
        sys.exit(1)

    # Extract binary
    try:
        subprocess.run(
            [OBJCOPY_CMD, "-O", "binary", obj_path, bin_path],
            check=True, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        print(f"Error objcopy for patch @0x{addr:X}:", file=sys.stderr)
        print(e.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    data = open(bin_path, "rb").read()
    # Cleanup
    for p in (asm_path, obj_path, bin_path):
        try:
            os.remove(p)
        except OSError:
            pass

    # Strip first two words (address + size)
    if len(data) < 8:
        print(f"Unexpected output length for patch @0x{addr:X}", file=sys.stderr)
        sys.exit(1)
    return data[8:]


def main(patch_file, output_file):
    text = open(patch_file, 'r').read()
    patches = parse_patches(text)

    with open(output_file, 'w') as f:
        for addr, insns in patches.items():
            patch_bytes = assemble_with_macros(addr, insns)
            hex_line = " ".join(f"{b:02X}" for b in patch_bytes)
            # write to file
            f.write(f".data 0x{addr:X}\n")
            f.write(f"{hex_line}\n")
            f.write(".eod\n\n")
            # also print to console
            print(f".data 0x{addr:X}")
            print(hex_line)
            print(".eod\n")

    print(f"Output written to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: {sys.argv[0]} <patches.txt> [output.txt]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    if len(sys.argv) == 3:
        output_file = sys.argv[2]
    else:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}-rgloader{ext}"

    main(input_file, output_file)
