#!/bin/bash

# Get the build arguments
COMMIT_HASH=$1

if [ -z "$COMMIT_HASH" ]; then
  echo "No commit hash provided, using 'Unknown'"
  COMMIT_HASH="Unknown"
fi

# Update the __init__.py file with the values
sed -i "s/__commit__ = \".*\"/__commit__ = \"$COMMIT_HASH\"/" /flowcase/__init__.py

echo "Injected values into __init__.py:"
echo "  Commit hash: $COMMIT_HASH"
