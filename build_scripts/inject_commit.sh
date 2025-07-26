#!/bin/bash

# Get the commit hash from the build argument
COMMIT_HASH=$1

if [ -z "$COMMIT_HASH" ]; then
  echo "No commit hash provided, using 'Unknown'"
  COMMIT_HASH="Unknown"
fi

# Update the __init__.py file with the commit hash
sed -i "s/__commit__ = \".*\"/__commit__ = \"$COMMIT_HASH\"/" /flowcase/__init__.py

echo "Injected commit hash: $COMMIT_HASH into __init__.py"