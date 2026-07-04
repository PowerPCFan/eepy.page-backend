# eepy.page-backend

The backend for https://www.eepy.page/, a free subdomain registrar

Please open issues on the frontend repo unless they are specific to the backend's code: https://github.com/PowerPCFan/eepy.page-frontend/

## Contribution guidelines

- Write code with type hinting
- Run tests and follow Ruff and Pyright/Pylance guidelines
- Push to your fork
- Make a PR to eepy.page-backend dev branch

## Setting up your development environmnet
### Python
#### Required Version
- Python 3.12 or later
#### Python Environment (Linux/macOS):
1. `python3 -m venv venv`
2. `source ./venv/bin/activate`
3. `python3 -m pip install -r requirements.txt`
#### Python Environment (Windows PowerShell):
1. `py -m venv venv`
2. `./venv/scripts/activate.ps1`
3. `py -m pip install -r requirements.txt`  
*If `py` cannot be found, try `python3` and `python`, however modern Python installs on Windows will likely use `py`*
### IDE
The intended IDE for working on this project is Visual Studio Code. All you need to do to get it set up is install the recommended extensions for this project. If you'd rather manually install them:
- Python (`ms-python.python`) (required)
- Ruff (`charliermarsh.ruff`)
- Pylance (`ms-python.vscode-pylance`)
- GitHub Local Actions (`SanjulaGanepola.github-local-actions`)

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

## How to run tests
Tests will automatically be ran when you open a pull request or push code, but you should still run them after writing code.

I recommend using the VSCode extension `SanjulaGanepola.github-local-actions` and running tests via the GitHub action. This ensures that your code is tested in a clean, reproducible environment for consistency across developers' machines. Additionally, you don't have to worry about setting up a MongoDB instance for tests.

How to use the extension:
1. Install it.
2. On your VSCode sidebar, find the GitHub Local Actions icon and click it. You may need to click the "Additional Views" button (...) to find it, if you have a lot of extensions installed.
3. At the top of the sidebar view, ensure that all components are installed. If any are missing, click the install button.
4. In the "Workflows" tab, open the "Test checks" dropdown. You should see "pytest", "ruff", and "pyright".
5. There's no need to run pyright or ruff, so what you want is pytest. Click the green play button next to the "pytest" option.
6. Your integrated terminal will open with a simple picker. You want to select the "medium" image. Medium is only 500MB and installs quickly. Do NOT select Large, it's 20GB and will unpack to around 75GB on disk.
7. `act` (the tool that GitHub Local Actions uses) will run the test, just as if it's being ran in a GitHub CI/CD pipeline. Please wait for the tests to complete. Once they're done, you should be able to see the test results in the same terminal. 

## A note on tests
If you add a new feature, I request that you add tests for it, if possible.