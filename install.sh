#!/bin/bash

# Check architecture
arch=$(uname -m)
if [[ "$arch" != "x86_64" && "$arch" != "arm64" ]]; then
    echo "Error: Unsupported architecture $arch. Exiting script."
    exit 1
fi

# Determine the appropriate architecture for the orb command
if [ "$arch" = "arm64" ]; then
    short_arch="aarch64"
else
    short_arch="x64"
fi

# Get version from API
version=$(curl -s "https://api.github.com/repos/doroved/proxer/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')

# Name of the downloaded file
downloaded_file="proxer_${version}_${short_arch}.dmg"

# Download the file
curl -OL "https://github.com/doroved/proxer/releases/download/v${version}/$downloaded_file"

# Check if the file exists in ~/Downloads, if not - move it
if [ ! -f "$HOME/Downloads/$downloaded_file" ]; then
    mv "$downloaded_file" "$HOME/Downloads/"
    echo "File moved to ~/Downloads/"
fi

# Remove quarantine from the file
if xattr "$HOME/Downloads/$downloaded_file" | grep -q "com.apple.quarantine"; then
    xattr -d com.apple.quarantine "$HOME/Downloads/$downloaded_file"
    echo "Quarantine removed from file $HOME/Downloads/$downloaded_file"
fi

# Run the file
open "$HOME/Downloads/$downloaded_file"
