# cli_demo.py
import getpass
from db import init_db
from users import create_user, login, get_user, update_password, disable_user, delete_user, find_user_by_email, UserError

def main():
    init_db()
    print("Users CLI demo")
    while True:
        print("\nCommands: create, login, get, passwd, disable, delete, exit")
        cmd = input("cmd> ").strip().lower()
        try:
            if cmd == "create":
                username = input("username: ")
                email = input("email: ")
                pwd = getpass.getpass("password: ")
                uid = create_user(username, email, pwd)
                print("created user id:", uid)
            elif cmd == "login":
                email = input("email: ")
                pwd = getpass.getpass("password: ")
                info = login(email, pwd)
                print("login ok:", info)
            elif cmd == "get":
                email = input("email: ")
                u = find_user_by_email(email)
                print(u)
            elif cmd == "passwd":
                email = input("email: ")
                u = find_user_by_email(email)
                if not u:
                    print("user not found")
                    continue
                newp = getpass.getpass("new password: ")
                update_password(u["id"], newp)
                print("password updated")
            elif cmd == "disable":
                email = input("email: ")
                u = find_user_by_email(email)
                if not u:
                    print("user not found")
                    continue
                disable_user(u["id"])
                print("disabled")
            elif cmd == "delete":
                email = input("email: ")
                u = find_user_by_email(email)
                if not u:
                    print("user not found")
                    continue
                delete_user(u["id"])
                print("deleted")
            elif cmd == "exit":
                break
            else:
                print("unknown cmd")
        except UserError as e:
            print("ERROR:", e)
        except Exception as e:
            print("EXCEPTION:", e)

if __name__ == "__main__":
    main()
