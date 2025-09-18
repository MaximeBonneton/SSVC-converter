# SSVC Vulnerability Prioritization Tool

A command-line tool to automate vulnerability prioritization using the CISA's Stakeholder-Specific Vulnerability Categorization (SSVC) framework. This script reads a CSV file containing vulnerability data, calculates the SSVC decision path for each entry, and generates a new, enriched CSV report with detailed, human-readable results.

## Features

* **Automated Prioritization**: Implements the complete CISA SSVC decision tree.
* **CSV Processing**: Reads vulnerability data directly from a `.csv` file.
* **Robust Error Handling**: Identifies and flags rows with invalid or missing data in the final report without crashing.
* **Detailed Reporting**: Creates a new CSV file containing all original data plus new columns for:
    * Standardized input metrics.
    * Individual CVSS metric values.
    * Intermediate SSVC decision parameters (`Exploitation`, `Automatable`, `Technical Impact`).
    * The final `SSVC Action` (`Act`, `Attend`, `Track*`, `Track`).
* **Human-Readable Output**: Both column headers and metric values in the final report are translated into clear, descriptive text.

---

## Prerequisites

* Python 3.7+
* `pip` and `venv` (usually included with Python)

---

## ⚙️ Installation

**1. Clone the repository**
(Or simply place the `main.py` and `ssvc_converter.py` files in a new project folder).

**2. Create and activate a virtual environment**
It is highly recommended to use a virtual environment to manage project dependencies.
```bash
# Create the virtual environment
python3 -m venv venv

# Activate it (on Linux/macOS)
source venv/bin/activate

# On Windows, use:
# venv\Scripts\activate