#!/usr/bin/env bash
# setup_server_files.sh  (run ONCE on the server VM before baseline capture)
# Creates the test files that traffic_gen_server.sh will serve via HTTP/scp.
mkdir -p /var/www/html/testfiles
dd if=/dev/urandom of=/var/www/html/testfiles/file_1mb.bin bs=1M count=1 2>/dev/null
dd if=/dev/urandom of=/var/www/html/testfiles/file_5mb.bin bs=1M count=5 2>/dev/null
dd if=/dev/urandom of=/var/www/html/testfiles/file_10mb.bin bs=1M count=10 2>/dev/null
echo "Test files created in /var/www/html/testfiles/"