# eepy.page-backend

The backend for https://www.eepy.page/, a free subdomain registrar

Please open issues on the frontend repo unless they are specific to the backend's code: https://github.com/PowerPCFan/eepy.page-frontend/

## Contribution guidelines

- Write code with type hinting
- Run pytest and type checks
- Push to your fork
- Make a PR to eepy.page-backend dev branch

## How to set up your Python environment
### Prerequisites
- Python 3.12 or later
### Linux/macOS:
1. `python3 -m venv venv`
2. `source ./venv/bin/activate`
3. `python3 -m pip install -r requirements.txt`
### Windows (PowerShell):
1. `py -m venv venv`
2. `./venv/scripts/activate.ps1`
3. `py -m pip install -r requirements.txt`  
*If `py` cannot be found, try `python3` and `python`, however modern Python installs on Windows will likely use `py`*

## How to get type checking working
1. Install the `ms-python.vscode-pylance` extension from the Visual Studio Code Marketplace

## How to get linting working
1. Install Ruff from the Visual Studio Code Marketplace (`charliermarsh.ruff`)
2. Install Ruff using `pip` (**note:** if you already ran the commands in "**How to set up your Python environment**", you're good!)
3. It should be good now! `.vscode/settings.json` and `ruff.toml` will automatically set up the proper settings for you

## A note on linting and type checking
Upon pushing or opening a PR, tests will run that automatically scan your code with Pyright and Ruff. Please ensure all linting or type checking errors are fixed or suppressed before opening a PR.

Pylance will automatically check as you code and so will Ruff, but here are some useful Ruff commands:
- **Checking Files: `ruff check .`**  
  Scans files recursively from your current directory for linting issues. Replace the `.` with a file or directory path if you'd like to further constrain the check.
  **Params**:
    - ⭐ `--fix`: fixes linting errors that are marked as fixable
      - `--unsafe-fixes`: when paired with `--fix`, runs fixes that are marked as fixable but potentially unsafe or could change code behavior
    - ⭐ `--diff`: shows a diff of what changes *would* be made if you ran `--fix`
    - `--watch`: keeps terminal open and re-scans on file save
    - `--statistics`: shows error code counts
- **Formatting Files: `ruff format .`**  
  Recursively formats files starting in your current directory. Replace the `.` with a file or directory path if you'd like to constrain the formatting to one file or a subdirectory. Formatting does not impact code execution but it greatly improves code cleanliness and readability.
  **Params**:
    - ⭐ `--check`: tells you if files are formatted without actually modifying them
    - ⭐ `--diff`: shows a diff of what changes *would* be made when formatting
