import subprocess
import os
from datetime import datetime
from colorama import Fore, Style, init
import re

init(autoreset=True)

GF_PATTERNS = [
    "debug_logic", "idor", "img-traversal", "interestingEXT", "interestingparams",
    "interestingsubs", "jsvar", "lfi", "rce", "redirect",
    "sqli", "ssrf", "ssti", "xss"
]

SENSITIVE_EXTENSIONS_PATTERN = re.compile(
    r"/(admin|config|backup|logs|uploads|tmp|var|wp-content|vendor|node_modules|\.git|\.svn)|"
    r"\.log|\.sql|\.env|\.conf|\.bak|\.txt|\.json|\.xml|\.yaml|\.yml|\.ini|\.pem|\.key|\.cer|\.crt|"
    r"\.pfx|\.zip|\.tar|\.gz|\.7z|\.rar|\.tgz|\.rdp|\.ppk|\.sh|\.bat|\.ps1|\.php|\.py|\.java|\.js|"
    r"\.html|\.htaccess|\.DS_Store|config|settings|secrets|credentials|password|api_key|database|"
    r"dump|env|\.gitignore|\.htpasswd|wp-config\.php|robots\.txt|sitemap\.xml|web\.config|"
    r"package-lock\.json|composer\.lock",
    re.IGNORECASE
)

def run_command(command, description):
    print(f"{Fore.BLUE}[+] {description}{Style.RESET_ALL}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"{Fore.RED}[!] Command failed: {result.stderr.strip()}{Style.RESET_ALL}")
            return ""
    except Exception as e:
        print(f"{Fore.RED}[!] Exception: {e}{Style.RESET_ALL}")
        return ""

def write_file(filepath, content):
    with open(filepath, "w") as f:
        f.write(content + "\n")

def gf_filter(input_file, pattern, output_file):
    command = f"gf {pattern} < {input_file} | sort -u"
    filtered_output = run_command(command, f"Filtering with gf pattern: {pattern}")
    if filtered_output:
        write_file(output_file, filtered_output)
    return filtered_output

def main():
    domain = input(Fore.YELLOW + "Enter the domain (e.g. example.com): " + Style.RESET_ALL).strip()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = f"filtered-recon-{domain}-{timestamp}"
    os.makedirs(out_dir, exist_ok=True)

    subfinder_file = os.path.join(out_dir, "subdomains.txt")
    crt_file = os.path.join(out_dir, "crt_subdomains.txt")
    archive_file = os.path.join(out_dir, "archive_urls.txt")
    sensitive_file = os.path.join(out_dir, "sensitive_urls.txt")

    # 0. Run Subfinder
    subfinder_command = f"subfinder -d {domain} -all -recursive -silent"
    subfinder_output = run_command(subfinder_command, "Running Subfinder...")
    write_file(subfinder_file, subfinder_output)
    print(f"\n{Fore.GREEN}Subdomains from Subfinder:{Style.RESET_ALL}")
    print(subfinder_output)

    # 1. Get subdomains from crt.sh
    crt_command = (
        f"""curl -s "https://crt.sh/?q={domain}&output=json" | jq -r '.[].name_value' | """
        f"""grep -Po '(\\w+\\.{domain.replace('.', '\\.')})$' | sort -u"""
    )
    crt_output = run_command(crt_command, "Getting subdomains from crt.sh")
    write_file(crt_file, crt_output)
    print(f"\n{Fore.GREEN}Subdomains from crt.sh:{Style.RESET_ALL}")
    print(crt_output)

    # 2. Get historical URLs from archive.org
    archive_command = (
        f"""curl -G "https://web.archive.org/cdx/search/cdx" """
        f"""--data-urlencode "url=*.{domain}/*" """
        f"""--data-urlencode "collapse=urlkey" """
        f"""--data-urlencode "output=text" """
        f"""--data-urlencode "fl=original" """
    )
    archive_output = run_command(archive_command, "Getting archive.org URLs")

    # Deduplicate archive URLs early
    archive_lines = sorted(set(archive_output.splitlines()))
    archive_output = "\n".join(archive_lines)
    write_file(archive_file, archive_output)

    # 3. Filter for sensitive extensions using Python
    print(f"{Fore.BLUE}\n[+] Filtering sensitive file extensions...{Style.RESET_ALL}")
    filtered_lines = [line for line in archive_lines if SENSITIVE_EXTENSIONS_PATTERN.search(line)]
    sensitive_output = "\n".join(sorted(set(filtered_lines)))
    write_file(sensitive_file, sensitive_output)

    print(f"\n{Fore.GREEN}Sensitive files found in archive.org:{Style.RESET_ALL}")
    print(sensitive_output)

    # 4. Filter using gf patterns and print results
    for pattern in GF_PATTERNS:
        output_file = os.path.join(out_dir, f"{pattern}_urls.txt")
        gf_result = gf_filter(archive_file, pattern, output_file)
        if gf_result:
            print(f"\n{Fore.GREEN}[✓] {pattern.upper()} URLs found and saved to {output_file}:{Style.RESET_ALL}")
            print(gf_result)
        else:
            print(f"\n{Fore.YELLOW}[!] No {pattern.upper()} URLs found.{Style.RESET_ALL}")

    print(f"\n✅ {Fore.GREEN}Recon complete. Output in: {out_dir}/{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
