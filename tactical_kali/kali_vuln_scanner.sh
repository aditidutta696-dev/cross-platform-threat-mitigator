#!/bin/bash

# Define the target and directory
TARGET=$1
OUT_DIR="/home/aditi/Tactical_Kali"
OUT_FILE="$OUT_DIR/last_scan.txt"

# Create directory if it doesn't exist
mkdir -p "$OUT_DIR"

echo "--- Scan started at $(date) for $TARGET ---" > "$OUT_FILE"

# Run the scan and append to the file
nmap -F "$TARGET" >> "$OUT_FILE"

echo "--- Scan completed ---" >> "$OUT_FILE"
