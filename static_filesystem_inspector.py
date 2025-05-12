import os
import hashlib
from collections import defaultdict
import sys
from contextlib import redirect_stdout

def get_package_files_from_rootfs(rootfs_path, package_name):
    """Extract the list of files for a package from a static root filesystem."""
    list_file = os.path.join(rootfs_path, 'var/lib/dpkg/info', f'{package_name}.list')
    if not os.path.exists(list_file):
        print(f"List file not found: {list_file}")
        return []

    with open(list_file, 'r') as f:
        files = [os.path.join(rootfs_path, line.strip().lstrip('/')) for line in f.readlines()]
    return [f for f in files if os.path.isfile(f) or os.path.islink(f)]

def compute_sha256(filepath):
    """Compute SHA256 hash of a file, resolving symlinks to actual content."""
    if os.path.islink(filepath):
        target = os.path.realpath(filepath)
        #print (f"Resolving symlink: {filepath}" f"-> {target}")
        if not os.path.isfile(target):
            return f"symlink -> {target} (target missing)"
        filepath = target

    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def inspect_packages(rootfs_path, packages):
    file_hash_map = defaultdict(list)

    for package in packages:
        #print(f"\nInspecting package: {package}")
        files = get_package_files_from_rootfs(rootfs_path, package)
        for file_path in files:
            hash_value = compute_sha256(file_path)
            #print(f"{file_path} -> {hash_value}")
            file_hash_map[(file_path, hash_value)].append(package)

    return file_hash_map

def print_summary(file_hash_map, rootfs_path):
    print("\n=== Shared Files Summary ===")
    for (file_path, hash_value), packages in file_hash_map.items():
        if len(packages) > 1:
            rel_path = os.path.relpath(file_path, rootfs_path)
            print(f"Shared: {rel_path} -> {hash_value}")
            print(f"  Packages: {', '.join(packages)}\n")

if __name__ == "__main__":
    # Adjust path and packages for extracted container
    rootfs_dir = "/Users/sonu/tmp/Analysis/Step3/tmp_devlake"
    
    with open('actual-files.sha256', 'r') as file:
        #list_files = [os.path.basename(line.strip().replace('.list', '')) for line in file if line.endswith('.list\n')]
  
        packages_to_inspect = ["python3.11", "python3.11-minimal", "python3.11-dev", "libpython3.11:arm64", "libpython3.11-dev:arm64","libpython3.11-minimal:arm64", "libpython3.11-stdlib:arm64"]

       #list_files.sort()
    #packages_to_inspect = list_files
    output_file = "output.txt"  # Specify output file path
    with open(output_file, 'w') as f:
        with redirect_stdout(f):
            result_map = inspect_packages(rootfs_dir, packages_to_inspect)
            print_summary(result_map, rootfs_dir)