#!/bin/sh
# This pre-hook must be set on your .git folder, move this file to .git/hooks/pre-push
echo ":: Git push detected: Running credential scanner before sending to remote ::"
python3 scanner.py
status=$?
if [ "$status" -ne 0 ]; then
    echo ""
    echo "Push blocked: possible secret detected!"
    exit "$status"
fi
echo ":: No secrets found. Proceeding with git push ::"
exit 0
