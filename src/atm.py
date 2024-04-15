#! /usr/bin/env python

from ssh import client

if __name__ == "__main__":
    atm = client.SSHClient(port=12345)
    print(f"Looking for bank at {atm._host} on port {atm._port}...")
    atm.connect()
    actions = {
        "1": ("Check balance", 1),
        "2": ("Deposit", 2),
        "3": ("Withdraw", 3)
    }
    while (1):
        print("\nWhat would you like to do?")
        print("1: Check balance")
        print("2: Deposit money")
        print("3: Withdraw money")
        print("4: Exit")
        choice = input("Enter option (1-4): ")

        if choice == "4":
            print("Thank you for using the ATM. Goodbye!")
            atm.say_goodbye(choice)
            break
        elif choice in actions:
            action, header = actions[choice]
            if choice == "2" or choice == "3":
                amount = int(input(f"How much would you like to {action.lower()}? $"))
                if amount > 4294967295:
                    print("ERROR: Amount too high to {action.lower()}")
                else:
                    atm.change_balance(choice, amount)
            else:
                atm.check_balance(choice)
        else: print("Invalid option, please try again.")

