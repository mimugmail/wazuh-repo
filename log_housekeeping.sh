#!/bin/bash

# Script ohne Parameter ausführen, es löscht Logs und Ordner älter als 6 Monate

# Paths to the log directories
ARCHIVES_DIR="/var/ossec/logs/archives"
ALERTS_DIR="/var/ossec/logs/alerts"

# This function removes logs and folders older than 6 months
function cleanup_logs() {
    local dir="$1"

    # Find directories older than 6 months and remove them
    find "$dir" -mindepth 2 -maxdepth 2 -type d -mtime +180 -exec rm -r {} +

    # Remove empty year directories
    find "$dir" -mindepth 1 -maxdepth 1 -type d -empty -delete
}

# Cleanup the directories
cleanup_logs "$ARCHIVES_DIR"
cleanup_logs "$ALERTS_DIR"

echo "Cleanup complete!"
