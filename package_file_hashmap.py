# Enhanced static_filesystem_inspector.py for cross-ecosystem support and enriched hash mapping (with Alpine and RPM support)

import os
import hashlib
import subprocess
import json

IMAGES = [
    "redhat_ubi8_latest"
]

ROOT_FS_DIR = "fs_digests"
OUTPUT_DIR = "package_file_hash_maps"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def detect_ecosystem(rootfs_path):
    if os.path.exists(os.path.join(rootfs_path, "var/lib/dpkg/info")):
        return "debian"
    elif os.path.exists(os.path.join(rootfs_path, "lib/apk/db/installed")):
        return "alpine"
    elif os.path.exists(os.path.join(rootfs_path, "var/lib/rpm")):
        return "rpm"
    else:
        return "unknown"


def get_all_packages_debian(rootfs_path):
    info_dir = os.path.join(rootfs_path, 'var/lib/dpkg/info')
    packages = []
    if os.path.exists(info_dir):
        for entry in os.listdir(info_dir):
            if entry.endswith('.list'):
                packages.append(entry.replace('.list', ''))
    return sorted(set(packages))


def get_package_files_debian(rootfs_path, package_name):
    list_file = os.path.join(rootfs_path, 'var/lib/dpkg/info', f'{package_name}.list')
    if not os.path.exists(list_file):
        return []
    with open(list_file, 'r') as f:
        files = [os.path.join(rootfs_path, line.strip().lstrip('/')) for line in f.readlines()]
    return [f for f in files if os.path.exists(f)]


def get_all_packages_alpine(rootfs_path):
    db_file = os.path.join(rootfs_path, "lib/apk/db/installed")
    packages = []
    if os.path.exists(db_file):
        with open(db_file, 'r') as f:
            for line in f:
                if line.startswith('P:'):
                    packages.append(line.strip().split('P:')[1])
    return sorted(set(packages))


def get_package_files_alpine(rootfs_path):
    db_file = os.path.join(rootfs_path, "lib/apk/db/installed")
    pkg_files = {}
    current_pkg = None
    if os.path.exists(db_file):
        with open(db_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('P:'):
                    current_pkg = line[2:].strip()
                elif line.startswith('F:') and current_pkg:
                    filepath = line[2:].strip()
                    full_path = os.path.join(rootfs_path, filepath.lstrip('/'))
                    if os.path.exists(full_path):
                        pkg_files.setdefault(current_pkg, []).append(full_path)
    return pkg_files


def get_package_files_rpm(rootfs_path):
    pkg_files = {}
    rpm_query_path = os.path.join(rootfs_path, 'usr/bin/rpm')
    if not os.path.exists(rpm_query_path):
        return pkg_files

    try:
        result = subprocess.run(["chroot", rootfs_path, "/usr/bin/rpm", "-qa", "--qf", "%{NAME}\n"], capture_output=True, text=True)
        packages = result.stdout.strip().splitlines()
        for pkg in packages:
            query = subprocess.run(["chroot", rootfs_path, "/usr/bin/rpm", "-ql", pkg], capture_output=True, text=True)
            for line in query.stdout.strip().splitlines():
                full_path = os.path.join(rootfs_path, line.lstrip('/'))
                if os.path.exists(full_path):
                    pkg_files.setdefault(pkg, []).append(full_path)
    except Exception as e:
        print(f"[!] RPM extraction failed: {e}")
    return pkg_files


def compute_sha256(filepath):
    try:
        is_symlink = os.path.islink(filepath)
        symlink_target = os.readlink(filepath) if is_symlink else None
        real_path = os.path.realpath(filepath) if is_symlink else filepath

        if not os.path.isfile(real_path):
            return None, is_symlink, symlink_target, "broken symlink"

        hasher = hashlib.sha256()
        with open(real_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest(), is_symlink, symlink_target, get_file_type(real_path)
    except Exception:
        return None, False, None, "error"


def get_file_type(filepath):
    try:
        result = subprocess.run(["file", "-b", filepath], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def inspect_packages(rootfs_path, ecosystem):
    result = []
    if ecosystem == "debian":
        packages = get_all_packages_debian(rootfs_path)
        for package in packages:
            files = get_package_files_debian(rootfs_path, package)
            for file_path in files:
                hash_value, is_symlink, symlink_target, file_type = compute_sha256(file_path)
                rel_path = os.path.relpath(file_path, rootfs_path)
                if hash_value:
                    result.append({
                        "package": package,
                        "file": rel_path,
                        "sha256": hash_value,
                        "is_symlink": is_symlink,
                        "symlink_target": symlink_target,
                        "file_type": file_type
                    })
    elif ecosystem == "alpine":
        pkg_files_map = get_package_files_alpine(rootfs_path)
        for package, files in pkg_files_map.items():
            for file_path in files:
                hash_value, is_symlink, symlink_target, file_type = compute_sha256(file_path)
                rel_path = os.path.relpath(file_path, rootfs_path)
                if hash_value:
                    result.append({
                        "package": package,
                        "file": rel_path,
                        "sha256": hash_value,
                        "is_symlink": is_symlink,
                        "symlink_target": symlink_target,
                        "file_type": file_type
                    })
    elif ecosystem == "rpm":
        pkg_files_map = get_package_files_rpm(rootfs_path)
        for package, files in pkg_files_map.items():
            for file_path in files:
                hash_value, is_symlink, symlink_target, file_type = compute_sha256(file_path)
                rel_path = os.path.relpath(file_path, rootfs_path)
                if hash_value:
                    result.append({
                        "package": package,
                        "file": rel_path,
                        "sha256": hash_value,
                        "is_symlink": is_symlink,
                        "symlink_target": symlink_target,
                        "file_type": file_type
                    })
    else:
        print(f"[!] Ecosystem '{ecosystem}' not supported.")
    return result


for image_tag in IMAGES:
    print(f"[+] Processing image: {image_tag}")
    rootfs_path = os.path.join(ROOT_FS_DIR, f"fs-{image_tag}")
    ecosystem = detect_ecosystem(rootfs_path)
    print(f"[i] Detected ecosystem: {ecosystem}")

    result = inspect_packages(rootfs_path, ecosystem)

    output_path = os.path.join(OUTPUT_DIR, f"{image_tag}-package-file-hashes.json")
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"[✔] Saved enriched hash map to {output_path}")
