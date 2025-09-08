# 📖 Solidity Smart Contract LITEAuditor 🚀

Welcome to **Auditos**, a powerful tool for auditing Solidity smart contracts! 🔍 This project helps you identify vulnerabilities in your smart contracts using Slither, with a clean and user-friendly interface. Whether you're a developer or a security researcher, Auditos makes contract auditing a breeze. 😎

## 📋 Table of Contents
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [How to Run](#-how-to-run)
- [Avoiding Common Errors](#-avoiding-common-errors)
- [Directory Structure](#-directory-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features
- 🔎 Automated vulnerability detection using Slither
- 🛠️ Support for analyzing Solidity contracts with detailed issue reporting
- 📊 Structured output with severity levels (HIGH, MEDIUM, LOW, INFORMATIONAL)
- 🖥️ CLI interface powered by Typer for easy usage
- 🌐 Optional FastAPI-based web server for remote auditing
- 🛡️ Fallback analysis mode for robust auditing
- 📝 Comprehensive issue reporting with line numbers, contract names, and function details

---

## 📦 Prerequisites
Before you start, ensure you have the following installed:
- 🐍 **Python** (3.8+)
- 🛠️ **Solc** (Solidity compiler, install via `solcx`)
- 🔍 **Slither** (install via `pip install slither-analyzer`)
- 📦 **pip** for installing dependencies

---

## 🛠️ Installation
Follow these steps to set up Auditos locally:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/auditos.git
   cd auditos
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Or, install directly with:
   ```bash
   pip install -e .
   ```

4. **Verify Slither installation**:
   ```bash
   slither --version
   ```
   Ensure Slither is installed and accessible in your environment.

---

## 🚀 How to Run

1. Run an audit on a Solidity contract:
   ```bash
   python src/main.py
   ```
   This will analyze the contract and output any detected issues.

2. Example output:

```
  Audit completed. Found 4 issues.

HIGH ISSUES (1):
============================================================
1. Reentrancy Vulnerability
   📍 VulnerableContract • deposit() • Line 19
   📝 Reentrancy in VulnerableContract.withdraw(uint256) (contracts/VulnerableContract.sol#19-27):
        External calls:
        - (success,None) = msg.sender.call{value: amount}() (contracts/VulnerableContract.sol#22)
   ...


LOW ISSUES (1):
============================================================
1. Low Level Call
   📍 Line 19
   📝 Low level call in VulnerableContract.withdraw(uint256) (contracts/VulnerableContract.sol#19-27):
        - (success,None) = msg.sender.call{value: amount}() (contracts/VulnerableContract.sol#22)
   Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls
   ...


INFORMATIONAL ISSUES (2):
============================================================
1. VulnerableContract.changeOwner(address).newOwner (contracts/VulnerableContract.sol#14) lacks a zero-check on
   📍 Line 14
   📝 VulnerableContract.changeOwner(address).newOwner (contracts/VulnerableContract.sol#14) lacks a zero-check on :
                - owner = newOwner (contracts/VulnerableContract.sol#15)
   Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation

2. Incorrect Solidity Version
   📍 Unknown location
   📝 Version constraint ^0.8.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
        - FullInlinerNonExpressionSplitArgumentEvaluationOrder
        - MissingSideEffectsOnSelectorAccess
   ...
   ```
---

## 🛑 Avoiding Common Errors
To ensure a smooth experience, watch out for these pitfalls:

1. **Slither not found** ⚠️:
   - Ensure Slither is installed (`pip install slither-analyzer`).
   - Verify the executable is accessible by running `slither --version`.
   - On Windows, you may need to specify the Python executable: `python -m slither`.

2. **Contract path issues** 📂:
   - Provide the correct path to the Solidity file (e.g., `contracts/VulnerableContract.sol`).
   - Use absolute paths if relative paths fail.

3. **Solc version mismatch** 🔧:
   - Ensure the Solidity compiler version matches the `pragma` in your contract (`^0.8.0` in the example).
   - Install the correct version using `solcx`:
     ```bash
     python -m solcx.install v0.8.0
     ```

4. **Dependency issues** 📦:
   - Ensure all dependencies from `requirements.txt` are installed.
   - If you encounter version conflicts, update packages or use a clean virtual environment.

5. **Windows-specific issues** 🖥️:
   - Use shell execution for Slither on Windows (already handled in the code).
   - Ensure Python and Slither are in your PATH.

---

## 📂 Directory Structure
Here's a quick overview of the project structure:
```
auditos/
├── contracts/                  # 📜 Solidity contracts for testing
│   └── VulnerableContract.sol  # Example contract with vulnerabilities
├── src/                        # 🛠️ Source code
│   ├── core/                   # Core auditing logic
│   │   ├── analyzers/          # Slither and fallback analyzers
│   │   └── models/             # Data models (Issue, Severity)
│   └── main.py                 # CLI entry point
├── requirements.txt            # 📋 Project dependencies
└── README.md                   # 📖 This file
```

---

## 🤝 Contributing
We welcome contributions! 🥳 To get started:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome-feature`).
3. Commit your changes (`git commit -m "Add awesome feature"`).
4. Push to the branch (`git push origin feature/awesome-feature`).
5. Open a Pull Request.

Please ensure your code follows the existing style and includes tests where applicable.

---

## 📜 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Happy auditing with Auditos! 🎉 If you encounter any issues or have questions, feel free to open an issue on GitHub. Let's make smart contracts safer together! 💪
