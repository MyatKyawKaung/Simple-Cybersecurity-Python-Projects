## Usage Examples

Basic bulk scan
```
python vt_checker.py -i targets.txt -k api.key -o scan_results.txt
```

Bulk scan with CSV output
```
python vt_checker.py -i targets.txt -k api.key -o scan.txt --csv --csv-output results.csv
```

Add custom delay between requests (30 seconds)
```
python vt_checker.py -i large_list.txt -k api.key -o results.txt --delay 30
```
