GODFATHER V16.0 🛡️
Sensitive data can hide, but it can't escape the GodFather.

GODFATHER is an advanced, modular recon tool designed for high-speed mass hunting. It is built to swallow massive lists of URLs and extract the "gold"—Sensitive Secrets, Internal Endpoints, and Vulnerable Redirects—that others often miss .

🚀 KEY FEATURES

Secret Hunting (-ky): Uses optimized, high-speed regex patterns to sniff out AWS keys, GitHub tokens, Slack webhooks, and Google API keys.

Endpoint Discovery (-ep): Scrapes every URL to extract hidden internal paths and API endpoints like /api/v2/admin/config_test.

PoC Mode (-poc): Automatically tests for 403 Forbidden bypasses using custom headers and checks for Open Redirect vulnerabilities.

Full Automation (-all): The "Master Switch" that turns on every scan engine at once—Secrets, Endpoints, and PoCs—for high-impact results.

🛠️ INSTALLATION

Clone the repository and install the necessary dependencies:

git clone https://github.com/D-666-V/THE_GOD_FATHER.git
cd THE_GOD_FATHER
pip3 install -r requirements.txt

📖 USAGE

Provide your list of target URLs and choose your hunting mode:

Full Chaos Mode (Secrets + Endpoints + PoCs)
python3 GOD_FATHER.py -i targets.txt -all -v

Target Secrets specifically
python3 GOD_FATHER.py -i targets.txt -ky -v

📊 PROOF OF WORK
<p align="center">
  <img src="https://github.com/user-attachments/assets/f4ed863c-c9b0-4c7a-8500-46856b56e9d8" width="900" alt="GodFather Recon Tool Findings">
</p>

Successfully capturing live findings on major targets like Adidas, Snyk, and Fireblocks.

⚠️ DISCLAIMER

This tool is for educational purposes and authorized security testing only. The developer is not responsible for any misuse or damage caused by this program. Use it ethically and only on targets you have permission to test.

🤝 CREDITS & COMMUNITY

Developer: Dharmveer 

Learning Hub: Proud student at Cyberous
