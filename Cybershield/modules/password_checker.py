"""
Password strength and security checker module
"""
# modules/password_checker.py

import re  # 're' is Python's Regular Expression library
           # It lets you search for patterns inside strings
           # Example: "does this string contain a number?"

def check_password_strength(password):
    """
    This function takes a password string as input,
    checks it against multiple rules,
    and returns a score + feedback list.
    """

    score = 0          # We'll add points for each rule the password passes
    feedback = []      # A list to collect advice messages for the user
    issues = []        # A list to collect what's wrong with the password

    # -------------------------------------------------------
    # RULE 1: Check password length
    # -------------------------------------------------------
    length = len(password)

    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    elif length < 12:
        score += 1
        feedback.append("Decent length, but 12+ characters is stronger")
    elif length < 16:
        score += 2
        feedback.append("Good length (12-15 characters)")
    else:
        score += 3
        feedback.append("Excellent length (16+ characters)")

    # -------------------------------------------------------
    # RULE 2: Check for uppercase letters (A-Z)
    # re.search() scans the string for any match to the pattern
    # [A-Z] means "any uppercase letter"
    # -------------------------------------------------------
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("Contains uppercase letters ✓")
    else:
        issues.append("Add uppercase letters (A-Z)")

    # -------------------------------------------------------
    # RULE 3: Check for lowercase letters (a-z)
    # -------------------------------------------------------
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("Contains lowercase letters ✓")
    else:
        issues.append("Add lowercase letters (a-z)")

    # -------------------------------------------------------
    # RULE 4: Check for digits (0-9)
    # \d means "any digit" in regex
    # -------------------------------------------------------
    if re.search(r'\d', password):
        score += 1
        feedback.append("Contains numbers ✓")
    else:
        issues.append("Add at least one number (0-9)")

    # -------------------------------------------------------
    # RULE 5: Check for special characters
    # [!@#$%^&*(),...] means "any of these characters"
    # -------------------------------------------------------
    if re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
        score += 1
        feedback.append("Contains special characters ✓")
    else:
        issues.append("Add special characters (!@#$%^&* etc.)")

    # -------------------------------------------------------
    # RULE 6: Check for common weak passwords
    # This is a small hardcoded list — in a real system
    # you'd load thousands from a file
    # -------------------------------------------------------
    common_passwords = [
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "abc123", "111111", "iloveyou", "welcome",
        "monkey", "dragon", "master", "sunshine", "princess"
    ]

    # .lower() converts the password to lowercase before comparing
    # so "PASSWORD" and "password" both get caught
    if password.lower() in common_passwords:
        score = 0  # Override — these are always weak regardless of other rules
        issues.append("This is a commonly used password — extremely dangerous!")

    # -------------------------------------------------------
    # RULE 7: Check for repeated characters like "aaaa" or "1111"
    # The pattern (.)\1{2,} means:
    #   (.) = capture any single character
    #   \1  = that same character again
    #   {2,} = 2 or more additional times
    # So it matches "aaa", "1111", "####", etc.
    # -------------------------------------------------------
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 1)  # Deduct 1 point but don't go below 0
        issues.append("Avoid repeating characters (e.g., 'aaa', '111')")

    # -------------------------------------------------------
    # DETERMINE STRENGTH LABEL based on final score
    # Maximum possible score = 3 (length) + 1 + 1 + 1 + 1 = 7
    # -------------------------------------------------------
    if score <= 1:
        strength = "VERY WEAK"
        strength_level = 1
    elif score <= 2:
        strength = "WEAK"
        strength_level = 2
    elif score <= 3:
        strength = "MODERATE"
        strength_level = 3
    elif score <= 5:
        strength = "STRONG"
        strength_level = 4
    else:
        strength = "VERY STRONG"
        strength_level = 5

    # -------------------------------------------------------
    # Return everything as a dictionary
    # A dictionary lets us package multiple values together
    # and access them by name later
    # -------------------------------------------------------
    return {
        "password": password,
        "score": score,
        "max_score": 7,
        "strength": strength,
        "strength_level": strength_level,  # 1 to 5 (used for GUI progress bar later)
        "feedback": feedback,
        "issues": issues
    }


def display_password_results(result):
    """
    This function takes the dictionary returned by check_password_strength()
    and prints it in a clean, readable format.
    """

    print("\n" + "="*50)
    print("       PASSWORD STRENGTH ANALYSIS")
    print("="*50)
    print(f"Password : {'*' * len(result['password'])}")  # Hide the actual password
    print(f"Score    : {result['score']} / {result['max_score']}")
    print(f"Strength : {result['strength']}")

    # Visual strength bar using simple characters
    # strength_level goes from 1 to 5
    bar_filled = "█" * result['strength_level']
    bar_empty  = "░" * (5 - result['strength_level'])
    print(f"Level    : [{bar_filled}{bar_empty}]")

    if result['feedback']:
        print("\n✅ What's good:")
        for item in result['feedback']:
            print(f"   • {item}")

    if result['issues']:
        print("\n❌ Issues found:")
        for item in result['issues']:
            print(f"   • {item}")

    print("="*50 + "\n")