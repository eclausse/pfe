#!/bin/bash
rm -fr files
rm -f vuln.db
mkdir files
touch vuln.db
cat migrations/user.sql | sqlite3 vuln.db
cat migrations/supplier.sql | sqlite3 vuln.db
cat migrations/access.sql | sqlite3 vuln.db