#!/usr/bin/env bash
# Transform, verify, upload and clear the output one slice at a time, for machines
# without room for the whole output. Usage:
#   export MACHINA_UPLOAD_TOKEN=...   (from the track page; upload.py asks again when it expires)
#   bash code/run_batches.sh gs://builders-machina-submissions-1120/teams/<team-id>/attempt-1/ [N]
# Finished slices are recorded in state/done-K and skipped on re-run.
set -euo pipefail
DEST="$1"; N="${2:-8}"; JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN)}"
for K in $(seq 1 "$N"); do
  [ -e "state/done-$K" ] && { echo "slice $K/$N already done"; continue; }
  echo "=== slice $K/$N: transform"
  python3 code/run.py transform --input ./input --state ./state --output ./cleaned-corpus --shard "$K/$N" --jobs "$JOBS"
  echo "=== slice $K/$N: verify"
  python3 code/run.py verify --state ./state --output ./cleaned-corpus --shard "$K/$N" --jobs "$JOBS"
  echo "=== slice $K/$N: upload"
  python3 upload.py --dest "$DEST" --corpus ./cleaned-corpus
  touch "state/done-$K"
  rm -rf ./cleaned-corpus
done
echo "All slices uploaded. Still to upload: code/ and README.txt"
