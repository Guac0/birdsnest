import os
import subprocess
import shutil
import tempfile
import random
import base64
from pathlib import Path

def seed_test_repo(repos_root, agent_id):
    """
    Creates a bare repo named {agent_id}.git and populates 
    'good' and 'bad' branches with random commits.
    """
    repo_name = f"{agent_id}.git"
    bare_path = os.path.join(repos_root, repo_name)
    
    # 1. Clear existing repo if it exists
    if os.path.exists(bare_path):
        shutil.rmtree(bare_path)
    
    # 2. Initialize Bare Repo
    subprocess.run(["git", "init", "--bare", repo_name], cwd=repos_root, check=True)

    # 3. Create a temporary workspace to build history
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(["git", "init"], cwd=tmpdir, check=True)
        
        # Initial Commit (Main)
        with open(os.path.join(tmpdir, "base.txt"), "w") as f:
            f.write("Initial Base Data")
        subprocess.run(["git", "add", "."], cwd=tmpdir, check=True)
        subprocess.run(["git", "commit", "-m", "Initial baseline"], cwd=tmpdir, check=True)
        
        # Setup Good Branch
        subprocess.run(["git", "checkout", "-b", "good"], cwd=tmpdir, check=True)
        _create_random_commits(tmpdir, "good", count=random.randint(2, 5))
        
        # Setup Bad Branch (branching off main again)
        subprocess.run(["git", "checkout", "main"], cwd=tmpdir, check=True)
        subprocess.run(["git", "checkout", "-b", "bad"], cwd=tmpdir, check=True)
        _create_random_commits(tmpdir, "bad", count=random.randint(2, 5))
        
        # 4. Push all branches to the bare repo
        subprocess.run(["git", "remote", "add", "origin", bare_path], cwd=tmpdir, check=True)
        subprocess.run(["git", "push", "origin", "--all"], cwd=tmpdir, check=True)

def _create_random_commits(wd, prefix, count):
    """Helper to generate dummy file changes and commits."""
    for i in range(count):
        fname = f"{prefix}_file_{i}.txt"
        with open(os.path.join(wd, fname), "w") as f:
            f.write(f"Data for {prefix} commit {i}")
        
        # Randomly modify an existing file to test 'modified' stats
        if i > 0:
            with open(os.path.join(wd, f"{prefix}_file_0.txt"), "a") as f:
                f.write("\nNew modification line")

        subprocess.run(["git", "add", "."], cwd=wd, check=True)
        subprocess.run(["git", "commit", "-m", f"Update for {prefix} iteration {i}"], cwd=wd, check=True)

# Example Usage:
# repos_dir = os.path.join(os.getcwd(), "repos")
# seed_test_repo(repos_dir, "1")
# seed_test_repo(repos_dir, "2")

def hash_id(*args):
    # hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields
    # Does not need to be secure
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
    #return hashlib.sha256(f"{ip}|{hostname}".encode()).hexdigest() #sha256 hash - too complex to use on frontend


if __name__ == "__main__":
    REPOS_DIR = os.path.join(os.path.dirname(Path(__file__).resolve()),"repos")
    if not os.path.exists(REPOS_DIR):
        os.makedirs(REPOS_DIR)
        
    for i in range(0, 5):
        print(f"Generating repo for Agent {i+1}...")
        possible_hostnames = ["webserver1","webserver2","fileshare1","fileshare2","dc01"]
        #hostname = random.choice(possible_hostnames)
        hostname = possible_hostnames[i]
        possible_ips = ["10.1.1.1","10.1.1.2","10.1.1.3","10.1.1.4","10.1.1.5"]
        #ip = random.choice(possible_ips)
        ip = possible_ips[i]
        possible_oses = ["Windows 10","Windows 2016Server","Ubuntu 16.03 Bookworm","RHEL 9.3","Rocky 8"]
        #os = random.choice(possible_oses)
        chosen_os = possible_oses[i]

        # The agent_id is computed but we use a unique prefix for test data to avoid collisions
        computed_agent_id = hash_id(f"test_agent_{i}", hostname, ip, chosen_os)
        seed_test_repo(REPOS_DIR, computed_agent_id)
    print("Done! Restart your Flask server and refresh the dashboard.")