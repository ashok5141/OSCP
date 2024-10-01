import re
import subprocess

def read_commit_ids(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return re.findall(r'\b[0-9a-f]{40}\b', content)

def run_git_show(commit_id):
    try:
        result = subprocess.run(['git', 'show', commit_id], 
                                capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running git show for commit {commit_id}: {e}")
        return None

def main():
    input_file = "git_output.txt"
    output_file = "git_show_output.txt"
    
    commit_ids = read_commit_ids(input_file)
    
    if not commit_ids:
        print("No valid commit IDs found in the file.")
        return

    with open(output_file, 'w') as out_file:
        for commit_id in commit_ids:
            output = run_git_show(commit_id)
            if output:
                out_file.write(f"Commit: {commit_id}\n")
                out_file.write(output)
                out_file.write("\n" + "="*80 + "\n\n")
    
    print(f"Git show output for all commits saved to {output_file}")

if __name__ == "__main__":
    main()
