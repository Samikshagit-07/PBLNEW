"""
CyberShield - A cybersecurity analysis tool
"""


# main.py
# This is the entry point of the entire CyberShield application
# Right now it only runs the password checker
# We'll expand this in every phase

from CyberShield.Cybershield.modules.password_checker import check_password_strength, display_password_results

def run_password_checker():
    print("\n" + "="*50)
    print("       CYBERSHIELD — PASSWORD CHECKER")
    print("="*50)
    print("Enter a password to analyze its strength.")
    print("Type 'quit' to exit.\n")

    while True:
        # getpass would hide input, but we'll use input() for now
        # so you can see what you're typing during development
        password = input("Enter password: ").strip()

        if password.lower() == 'quit':
            print("Exiting Password Checker.")
            break

        if not password:
            print("Please enter a password.\n")
            continue

        # Call the checker and display results
        result = check_password_strength(password)
        display_password_results(result)

if __name__ == "__main__":
    # __name__ == "__main__" means:
    # "only run this block if this file is run directly"
    # not when it's imported by another file
    run_password_checker()