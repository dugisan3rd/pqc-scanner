# pqc-scanner

pqc-scanner in python for SBOM & CBOM

# Prerequisite

## Linux

1. Make sure `curl` is installed which commonly located at `/usr/bin/curl`.
2. Install `syft` binary.
   ```
   curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
   ```

# Flow

1. Check OS version using `scripts/initial_check.py`.
2. If Linux,
   1. Install `Syft` (SBOM) and `Grype` (VA).
3. Else if Windows,
   1. Use the pre downloaded binary in /bin.
4.
