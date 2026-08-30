#!/bin/bash
# Patch c2-sink (vm904) netplan in place: attack /24 -> /31 via .13, on disk.
set -e
echo "=== stop vm904 (LVM live in guest) ==="
qm stop 904 2>&1 | tail -1 || true
sleep 3
qm status 904
export LVM_SYSTEM_DIR=/tmp/lvmdir
mkdir -p /tmp/lvmdir
cat > /tmp/lvmdir/lvm.conf <<'EOF'
devices {
  dir = "/dev"
  scan = [ "/dev" ]
  filter = [ "a|/dev/zd528.*|", "r|.*|" ]
  global_filter = [ "a|/dev/zd528.*|", "r|.*|" ]
  obtain_device_list_from_udev = 0
}
EOF
echo "=== activating ==="
vgchange -ay 2>&1 | tail -1
mkdir -p /mnt/c2root
mount -o rw /dev/ubuntu-vg/ubuntu-lv /mnt/c2root 2>&1 || mount -o rw /dev/ubuntu-vg/root /mnt/c2root 2>&1
echo "=== netplan files ==="
ls -la /mnt/c2root/etc/netplan/
echo "=== which file holds attack block ==="
grep -l "10.10.1.20" /mnt/c2root/etc/netplan/*.yaml 2>/dev/null
NP=$(grep -l "10.10.1.20" /mnt/c2root/etc/netplan/*.yaml 2>/dev/null | head -1)
echo "NP=$NP"
echo "=== before ==="
cat "$NP" 2>/dev/null
cp "$NP" "${NP}.bak-ssop" 2>/dev/null || true
python3 - "$NP" <<'PYEOF'
import sys
path = sys.argv[1]
lines = open(path).read().split("\n")
out = []
i = 0
patched = False
while i < len(lines):
    line = lines[i]
    out.append(line)
    # inside the attack block (4-space indent key), find the addresses list item
    if line.strip().startswith('- "10.10.1.20/24"') or line.strip().startswith('- 10.10.1.20/24'):
        indent = line[:len(line) - len(line.lstrip())]          # e.g. "      "
        out[-1] = line.replace("/24", "/31")
        # check next non-addresses content to decide where routes go;
        # simplest: insert routes right after this address line (same indent level as the list item)
        out.append(indent + "routes:")
        out.append(indent + "- to: \"10.10.1.10/31\"")
        out.append(indent + "  via: \"10.10.1.21\"")
        patched = True
        # skip any existing routes under attack to avoid duplication (we'll rely on ours)
        j = i + 1
        while j < len(lines) and lines[j].strip() and not lines[j].strip().startswith("- "):
            j += 1
        # do NOT consume following list items aggressively; let loop continue
    i += 1
if not patched:
    print("WARN: address line not found — file may use different format", file=sys.stderr)
    sys.exit(2)
open(path, "w").write("\n".join(out) + "\n")
print("PATCHED")
PYEOF
echo "=== after ==="
cat "$NP" 2>/dev/null
sync
umount /mnt/c2root 2>/dev/null
vgchange -an 2>&1 | tail -1
echo "=== start vm904 ==="
qm start 904 2>&1 | tail -1
echo "DONE"
