# pqc-scanner

pqc-scanner in python for SBOM & CBOM

# Prerequisite

## Linux

1. Make sure `curl` is installed which commonly located at `/usr/bin/curl`.
2. Install `syft` binary.
   ```
   curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
   ```
3. Install `grype` binary.
   ```
   curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
   ```

# Flow
1. Run `pqc_auto_scan.py` to scan
   ```
   sudo python3 pqc_auto_scan.py --path testing/DVWA --server 127.0.0.1
   ```
