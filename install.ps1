# If the python environment does not exist, create it
if (-not (Test-Path -Path ".venv")) {
    python -m venv .venv
}

Invoke-Expression -Command .\.venv\Scripts\activate
python.exe -m pip install --upgrade pip

Get-ChildItem -Recurse -Filter requirements.txt | ForEach-Object {
    python -m pip install -r $_.FullName
}