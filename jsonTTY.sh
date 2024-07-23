
#!/bin/bash

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Set relative directories
TTY_DIR="$SCRIPT_DIR/var/lib/cowrie/tty"
OUTPUT_DIR="$SCRIPT_DIR/var/log/cowrie/readable_tty"
HASH_DIR="$SCRIPT_DIR/var/log/cowrie/hashes"

# Ensure directories exist
mkdir -p "$OUTPUT_DIR" "$HASH_DIR"

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

  # Compare hashes to determine if the file has changed
  if [ "$current_hash" != "$previous_hash" ]; then
      # File has changed or is new, process the file
      echo "Processing $basefile, file has changed."

      # Initialize the JSON object
      json_object=$(jq -n --arg timestamp "$timestamp" --arg filename "$basefile" '{timestamp: $timestamp, filename: $filename, commands: []}')

      # Use playlog to convert binary log to text, clean up ANSI escape codes, and append each command to the JSON object
      commands=$(/home/cowrie/cowrie/bin/playlog -i -m 100000 "$ttyfile" | perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' | jq -Rc . | jq -cs .)

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