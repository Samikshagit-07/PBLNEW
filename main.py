# main.py

from modules.password_checker import check_password_strength, display_password_results
from modules.keylogger_detector import scan_for_keyloggers, display_scan_results


def run_password_checker():
    print("\n" + "="*50)
    print("       CYBERSHIELD — PASSWORD CHECKER")
    print("="*50)
    print("Type 'quit' to go back to the main menu.\n")

    while True:
        password = input("Enter password: ").strip()

        if password.lower() == 'quit':
            break

        if not password:
            print("Please enter a password.\n")
            continue

        result = check_password_strength(password)
        display_password_results(result)


def run_keylogger_scan():
    print("\n" + "="*50)
    print("    CYBERSHIELD — KEYLOGGER DETECTION SCAN")
    print("="*50)
    print("This will scan all running processes on your system.")
    print("It may take 5-15 seconds depending on your machine.\n")

    confirm = input("Start scan? (yes/no): ").strip().lower()

    if confirm in ('yes', 'y'):
        results = scan_for_keyloggers(verbose=True)
        display_scan_results(results)
    else:
        print("Scan cancelled.\n")


def main_menu():
    while True:
        print("\n" + "="*50)
        print("         CYBERSHIELD SECURITY ANALYZER")
        print("="*50)
        print("  [1] Password Strength Checker")
        print("  [2] Keylogger / Malware Process Scanner")
        print("  [3] Network Traffic Analyzer  (Phase 3)")
        print("  [0] Exit")
        print("="*50)

        choice = input("Select an option: ").strip()

        if choice == '1':
            run_password_checker()
        elif choice == '2':
            run_keylogger_scan()
        elif choice == '3':
            print("\n  [!] Network Analyzer coming in Phase 3.\n")
        elif choice == '0':
            print("\nExiting CyberShield. Stay safe!\n")
            break
        else:
            print("\n  Invalid option. Please choose 1, 2, 3, or 0.\n")


if __name__ == "__main__":
    main_menu()