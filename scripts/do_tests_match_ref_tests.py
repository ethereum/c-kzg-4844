#!/usr/bin/env python3

import glob
import hashlib
import json
import os
import tarfile
import tempfile
import urllib.request


def download_latest_tests(output_dir):
    """
    Download the latest KZG reference tests (including pre-releases).
    """
    with urllib.request.urlopen("https://api.github.com/repos/ethereum/consensus-spec-tests/releases") as response:
        releases = json.loads(response.read().decode())

    for asset in releases[0]["assets"]:
        if asset["name"] == "general.tar.gz":
            file_name = os.path.join(output_dir, asset["name"])
            download_url = asset["browser_download_url"]

    print(f"Downloading: {download_url}")
    with urllib.request.urlopen(download_url) as download_response:
        with open(file_name, "wb") as file:
            file.write(download_response.read())

    return file_name


def extract_tarfile(tests_tarfile, temp_dir):
    """
    The release artifact is a tar.gz file, this will extract it.
    """
    extract_dir = os.path.join(temp_dir, tests_tarfile + ".extracted")
    os.makedirs(extract_dir, exist_ok=True)
    with tarfile.open(tests_tarfile, "r:gz") as tar:
        tar.extractall(path=extract_dir)
    return extract_dir


def find_data_yaml_files(root_dir):
    """
    Get a list of all of the data.yaml files in the directory.
    """
    pattern = os.path.join(root_dir, "**", "data.yaml")
    data_yaml_files = glob.glob(pattern, recursive=True)
    return [f for f in data_yaml_files if "/kzg-mainnet/" in f]


def sha256_hash_file(file_path):
    """
    Get the sha256hash for some file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_normalized_file_to_hash_dict(files):
    """
    This creates a dictionary of normalized_path:sha256hash. By normalized, we
    mean the parts of the path which are different between local/reference
    tests are removed. If both test directories contain the same tests, these
    dictionaries are expected to be the same. If there is a missing/extra test,
    it will be caught.
    """
    d = {}
    for file in files:
        parts = file.split(os.path.sep)
        index = parts.index("kzg-mainnet") - 1
        key = os.path.sep.join(parts[index:])
        d[key] = sha256_hash_file(file)
    return d


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp_dir:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_tests_dir = os.path.join(script_dir, "../tests")
        local_tests = find_data_yaml_files(local_tests_dir)
        local_dict = create_normalized_file_to_hash_dict(local_tests)

        tests_tarfile = download_latest_tests(temp_dir)
        reference_tests_dir = extract_tarfile(tests_tarfile, temp_dir)
        reference_tests = find_data_yaml_files(reference_tests_dir)
        reference_dict = create_normalized_file_to_hash_dict(reference_tests)

        assert len(local_dict) == len(reference_dict)
        for key in reference_dict:
            assert local_dict[key] == reference_dict[key], key

        print("The local tests match the reference tests")
