from password_strenght import check_password_strength

def main():
    print("=== Password Strength Tester ===")

    username = input("Enter your username: ").strip()
    if username == "":
        username = None

    while True:
        print("\nType a password to test (or type 'exit' to quit):")
        pwd = input("> ")

        if pwd.lower() == "exit":
            break

        result = check_password_strength(pwd, username)

        print("\n--- RESULT ---")
        if result["is_strong"]:
            print("This password is STRONG!")
        else:
            print("This password is WEAK. Reasons:")
            for e in result["errors"]:
                print(" -", e)

        print("\n------------------------------")

if __name__ == "__main__":
    main()