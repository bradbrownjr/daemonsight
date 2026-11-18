"""CVE matching on the hub. Collectors send what is installed (collector/sources/inventory.py);
the hub downloads public vulnerability data (feeds.py), matches (match.py) and keeps
everything in its own SQLite file, <data_dir>/cve.db (store.py). Nothing here runs on a host."""
