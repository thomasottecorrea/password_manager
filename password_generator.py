import json
import getpass
import random
import string

# Function to generate new password
def generate_password(length=12, include_digits=True, include_symbols=True):
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase

    digits = string.digits if include_digits else ""
    symbols = string.punctuation if include_symbols else ""
    characters = lowercase_letters + uppercase_letters + digits + symbols
    length = max(length, 1)
    password = "".join(random.choice(characters) for i in range(length))
    return password

# Function to load password manager data from a JSON file
def load_data():
    try:
        with open('passwords.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Function to save password manager data to a JSON file
def save_data(data):
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)

# Function to encrypt the password
# Encryption function
def encrypt(password):
    encrypted_password = ""
    for char in password:
        # Shift each character by a fixed value (e.g., +1)
        encrypted_char = chr(ord(char) + 1)
        encrypted_password += encrypted_char
    return encrypted_password

# Decryption function
def decrypt(password):
    decrypted_password = ""
    for char in password:
        # Shift each character back by the fixed value (e.g., -1)
        decrypted_char = chr(ord(char) - 1)
        decrypted_password += decrypted_char
    return decrypted_password

# Function to add a new account
def add_account(data):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    create = input("\nMenu:\n1. I already have a password\n2. Create a password\nEnter your choice: ")
    if create == "2":
        password = generate_password()
        print("Your password is:",password)
        encrypted_password = encrypt(password)

        data[website] = {
            'username': username,
            'password': encrypted_password
        }
        save_data(data)
        print("Account added successfully!")
    else:
        password = getpass.getpass("Enter password: ")

        # Encrypt the password before storing
        encrypted_password = encrypt(password)

        data[website] = {
            'username': username,
            'password': encrypted_password
        }
        save_data(data)
        print("Account added successfully!")

def get_password(data):
    website = input("Enter website name: ")
    if website in data:
        account = data[website]
        decrypted_password = decrypt(account['password'])
        print("Username:", account['username'])
        print("Password:", decrypted_password)
    else:
        print("Account not found.")

def main():
    print("Password Manager")
    master_password = getpass.getpass("Enter master password: ")

    # Load data and check master password
    data = load_data()
    if not data.get('master_password'):
        data['master_password'] = master_password
        save_data(data)
        print("Master password created successfully.")
    elif master_password != data['master_password']:
        print("Incorrect master password. Exiting.")
        return

    while True:
        print("\nMenu:")
        print("1. Add Account")
        print("2. Get Password")
        print("3. Generate Password")
        print("4. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            add_account(data)
        elif choice == '2':
            get_password(data)
        elif choice == '3':
            generate_password()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.\n")

    print("Thank you for using Password Manager!")

main()

