# Get all .txt files in C:\<Choose the path> and create Output file its subdirectories
$txtFiles = Get-ChildItem -Path C:\Users\Ashok\Desktop -Filter *.txt -Recurse

# Create an output file where you want
#Powershell
#New-Item -Path C:\Users\username\Documents\emptyfile.txt -ItemType File
$outputFile = "C:\Users\Ashok\Desktop\output.txt"

# Loop through each .txt file and view its contents using the Type command
foreach ($file in $txtFiles) {
    # Write the file path to the output file
    Add-Content -Path $outputFile -Value "------------------------"
    Add-Content -Path $outputFile -Value $file.FullName
    Add-Content -Path $outputFile -Value "------------------------"
    
    # Write the file contents to the output file
    Get-Content -Path $file.FullName | Add-Content -Path $outputFile
}

Write-Host "Output saved to $outputFile"
