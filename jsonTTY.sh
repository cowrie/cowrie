#!/bin/bash

# Help message function
show_help() {
  echo "Usage: $(basename "$0") [OPTION]"
  echo "Run the script to process TTY logs and convert them to readable JSON format. Script uses playlog utility, jq and perl"
  echo ""
  echo "  -f    Run without performing hash checks on TTY files"
  echo "  -h    Display this help message and exit"
  echo ""
  echo "Without any options, the script will process all changed TTY files since the last run."
}

# Check for required tools: jq and perl
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq to continue."
    exit 1
fi

if ! command -v perl &> /dev/null; then
    echo "Error: perl is not installed. Please install perl to continue."
    exit 1
fi

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Set relative directories
TTY_DIR="$SCRIPT_DIR/var/lib/cowrie/tty"
OUTPUT_DIR="$SCRIPT_DIR/var/log/cowrie/readable_tty"
HASH_DIR="$SCRIPT_DIR/var/log/cowrie/hashes"

# Ensure directories exist
mkdir -p "$OUTPUT_DIR" "$HASH_DIR"

# Option and argument handling
skip_hash_check=false

while getopts 'fh' option; do
  case "$option" in
    f) skip_hash_check=true ;;
    h) show_help
       exit 0 ;;
    *) show_help
       exit 1 ;;
  esac
done

# Process each TTY file
for ttyfile in $TTY_DIR/*
do
  basefile=$(basename "$ttyfile")
  hashfile="$HASH_DIR/$basefile.hash"
  timestamp=$(date --iso-8601=seconds)

  # Compute current hash of the TTY file
  current_hash=$(sha256sum "$ttyfile" | awk '{print $1}')

  # Read the previous hash (if exists)
  previous_hash=""
  if [ -f "$hashfile" ]; then
      previous_hash=$(cat "$hashfile")
  fi

  # Compare hashes to determine if the file has changed or if hash check is skipped
  if $skip_hash_check || [ "$current_hash" != "$previous_hash" ]; then
      echo "Processing $basefile, hash check skipped."

      # Initialize the JSON object
      json_object=$(jq -n --arg timestamp "$timestamp" --arg filename "$basefile" '{timestamp: $timestamp, filename: $filename, commands: []}')

      # Use playlog to convert binary log to text, clean up ANSI escape codes, and append each command to the JSON object
      commands=$(/home/cowrie/cowrie/bin/playlog -i -m 100000 "$ttyfile" | strings |  perl -pe 's/\e\[[\d;]*[mGKHfJ]//g' | jq -Rc . | jq -cs .)

      # Check if commands is valid JSON
      if ! jq -e . <<<"$commands" > /dev/null; then
          echo "Error in JSON commands format"
          continue  # Skip this file or handle the error appropriately
      fi

      # Append commands to the JSON object
      json_object=$(echo "$json_object" | jq --argjson cmds "$commands" '.commands += $cmds')

      # Write the JSON object to the output file, removing newlines
      echo "$json_object" | tr -d '\n' > "$OUTPUT_DIR/$basefile.json"

      # Update hash file
      echo "$current_hash" > "$hashfile"
  else
      echo "Skipping $basefile, no changes detected."
  fi
done
