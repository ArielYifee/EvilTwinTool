import Attack as at

def attack():
    at.activate_monitor()
    network = at.networks_scan()
    at.deactivate_monitor()
    # user = at.users_scan()
    # at.start(network, user)


if __name__ == "__main__":
    print("Welcome")
    print("What do you wnat to do?:\n1. Attack.\n2. Defence")
    choice = input("Choose an option: ")
    if choice == "1":
        attack()
    elif choice == "2":
        pass #to be defence
    else:
        print("screw you guys.")
