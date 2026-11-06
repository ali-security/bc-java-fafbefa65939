#!/bin/sh
# Keep the job open until Travis has archived the Gradle result lines of this job's log,
# so a log fetched right after the job finishes is complete. Runs in after_script, which
# cannot change the build result. Polls every 20 s, gives up after 2100 s (Travis jobs are killed at 50 min).
url="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
waited=0
while [ "$waited" -lt 2100 ]; do
  if curl -fsSL "$url" 2>/dev/null | grep -Eq 'BUILD (SUCCESSFUL|FAILED) in [0-9]'; then
    echo "log archived after ${waited}s"
    exit 0
  fi
  echo "waiting for log archive... (${waited}s)"
  sleep 20
  waited=$((waited + 20))
done
echo "log archive still incomplete after ${waited}s"
exit 0
