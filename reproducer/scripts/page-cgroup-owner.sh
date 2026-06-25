#!/bin/bash
# Usage: sudo ./page-cgroup-owner.sh <file_path>
#
# For a file whose pages are in the page cache, shows which cgroup(s)
# the kernel charged those pages to. Requires root (reads pagemap and
# kpagecgroup).

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <file_path>" >&2
    exit 1
fi

FILE="$1"

if [[ ! -f "$FILE" ]]; then
    echo "Error: $FILE does not exist or is not a regular file" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root (need access to pagemap and kpagecgroup)" >&2
    exit 1
fi

# Build a map of cgroup inode -> cgroup path
declare -A CGROUP_MAP
while IFS= read -r -d '' dir; do
    ino=$(stat -c %i "$dir" 2>/dev/null) || continue
    CGROUP_MAP[$ino]="$dir"
done < <(find /sys/fs/cgroup -type d -print0 2>/dev/null)

python3 -c "
import mmap, os, struct, sys

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY)
size = os.fstat(fd).st_size
if size == 0:
    print('File is empty')
    sys.exit(0)

mm = mmap.mmap(fd, size, mmap.MAP_PRIVATE, mmap.PROT_READ)

# Touch every page to populate page table entries
for offset in range(0, size, 4096):
    _ = mm[offset]

pid = os.getpid()
page_size = 4096
num_pages = (size + page_size - 1) // page_size

# Get the base virtual address of the mmap
# Read /proc/self/maps to find our mapping
base_va = None
with open(f'/proc/{pid}/maps') as f:
    for line in f:
        if path in line and 'r--p' in line:
            base_va = int(line.split('-')[0], 16)
            break
        if path in line and 'r-xp' in line:
            base_va = int(line.split('-')[0], 16)
            break

if base_va is None:
    # Fallback: find any mapping of this file
    with open(f'/proc/{pid}/maps') as f:
        for line in f:
            if path in line:
                base_va = int(line.split('-')[0], 16)
                break

if base_va is None:
    print('Could not find mapping in /proc/self/maps', file=sys.stderr)
    sys.exit(1)

pagemap_fd = os.open(f'/proc/{pid}/pagemap', os.O_RDONLY)
kpagecgroup_fd = os.open('/proc/kpagecgroup', os.O_RDONLY)

cgroup_counts = {}
present = 0
not_present = 0

start_page = base_va // page_size

for i in range(num_pages):
    page_num = start_page + i
    os.lseek(pagemap_fd, page_num * 8, os.SEEK_SET)
    data = os.read(pagemap_fd, 8)
    if len(data) < 8:
        continue
    entry = struct.unpack('Q', data)[0]

    if not (entry & (1 << 63)):
        not_present += 1
        continue

    present += 1
    pfn = entry & ((1 << 55) - 1)

    os.lseek(kpagecgroup_fd, pfn * 8, os.SEEK_SET)
    cg_data = os.read(kpagecgroup_fd, 8)
    if len(cg_data) < 8:
        continue
    cg_ino = struct.unpack('Q', cg_data)[0]
    cgroup_counts[cg_ino] = cgroup_counts.get(cg_ino, 0) + 1

os.close(pagemap_fd)
os.close(kpagecgroup_fd)
mm.close()
os.close(fd)

total = present + not_present
print(f'File: {path}')
print(f'Size: {size} bytes ({num_pages} pages)')
print(f'Resident: {present}/{num_pages} pages ({present * 100 // num_pages}%)')
print(f'Not resident: {not_present} pages')
print()
print('Charged to:')
for ino, count in sorted(cgroup_counts.items(), key=lambda x: -x[1]):
    pct = count * 100 // present if present else 0
    kib = count * 4
    print(f'  inode={ino}  {count} pages ({kib} KiB, {pct}%)')
" "$FILE"

echo ""
echo "Cgroup inode lookup:"
# Re-run python to get the inodes, then resolve them
python3 -c "
import mmap, os, struct, sys

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY)
size = os.fstat(fd).st_size
if size == 0:
    sys.exit(0)
mm = mmap.mmap(fd, size, mmap.MAP_PRIVATE, mmap.PROT_READ)
for offset in range(0, size, 4096):
    _ = mm[offset]

pid = os.getpid()
page_size = 4096
num_pages = (size + page_size - 1) // page_size

base_va = None
with open(f'/proc/{pid}/maps') as f:
    for line in f:
        if path in line:
            base_va = int(line.split('-')[0], 16)
            break

if base_va is None:
    sys.exit(1)

pagemap_fd = os.open(f'/proc/{pid}/pagemap', os.O_RDONLY)
kpagecgroup_fd = os.open('/proc/kpagecgroup', os.O_RDONLY)
start_page = base_va // page_size
inodes = set()
for i in range(num_pages):
    page_num = start_page + i
    os.lseek(pagemap_fd, page_num * 8, os.SEEK_SET)
    data = os.read(pagemap_fd, 8)
    if len(data) < 8:
        continue
    entry = struct.unpack('Q', data)[0]
    if not (entry & (1 << 63)):
        continue
    pfn = entry & ((1 << 55) - 1)
    os.lseek(kpagecgroup_fd, pfn * 8, os.SEEK_SET)
    cg_data = os.read(kpagecgroup_fd, 8)
    if len(cg_data) < 8:
        continue
    inodes.add(struct.unpack('Q', cg_data)[0])
os.close(pagemap_fd)
os.close(kpagecgroup_fd)
mm.close()
os.close(fd)
for ino in sorted(inodes):
    print(ino)
" "$FILE" | while read -r ino; do
    cg_path="${CGROUP_MAP[$ino]:-unknown}"
    echo "  inode $ino -> $cg_path"
done
