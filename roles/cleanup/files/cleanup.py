import os
import shutil
import subprocess

def run_command(command):
    """Utility to run shell commands and log output."""
    try:
        print(f"Executing: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            print("  Success.")
        else:
            print(f"  Note: {result.stderr.strip() or 'Command skipped (not found).'}")
    except Exception as e:
        print(f"  Error: {e}")

def cleanup():
    # 1. Define the services to stop and disable
    services = [
        "stabvest-server",
        "stabvest-worker",
        "stabvest-apache2",
        "owlet-ssh"
    ]

    # 2. Define the directories to delete
    directories = [
        "/stabvest_server",
        "/owlet",
        "/stabvest"
    ]

    print("--- Starting Cleanup Process ---")

    # Stop and Disable Services
    for service in services:
        print(f"Managing service: {service}")
        # Stop the service
        run_command(["systemctl", "stop", f"{service}.service"])
        # Disable it so it doesn't start on boot
        run_command(["systemctl", "disable", f"{service}.service"])
        # Remove the unit file if it exists in common locations
        unit_path = f"/etc/systemd/system/{service}.service"
        if os.path.exists(unit_path):
            os.remove(unit_path)
            print(f"  Removed unit file: {unit_path}")

    # Reload systemd to apply service removals
    run_command(["systemctl", "daemon-reload"])
    run_command(["systemctl", "reset-failed"])

    # Delete Directories
    for directory in directories:
        if os.path.exists(directory):
            try:
                print(f"Deleting directory: {directory}")
                shutil.rmtree(directory)
                print("  Successfully deleted.")
            except Exception as e:
                print(f"  Failed to delete {directory}: {e}")
        else:
            print(f"Directory not found: {directory} (skipping)")

    print("--- Cleanup Complete ---")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script must be run as root (use sudo).")
        exit(1)
    else:
        #confirm = input("This will PERMANENTLY delete these services and folders. Continue? (y/N): ")
        #if confirm.lower() == 'y':
        cleanup()
        #else:
        #    print("Operation cancelled.")