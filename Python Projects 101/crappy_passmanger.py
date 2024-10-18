import hashlib
import getpass
import secrets
import string
import os

# Dictionary to store usernames and hashed passwords
password_manager = {}

# Function to hash a password using SHA-256
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Function to generate a random password
def generate_password(length: int) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Function to get user input for password length with validation
def get_password_length() -> int:
    while True:
        try:
            length = int(input("Enter your desired password length (12-60): "))
            if 12 <= length <= 60:
                return length
            else:
                print("Error: Password length must be between 12 and 60 characters.")
        except ValueError:
            print("Error: Please enter a valid integer.")

# Function to get a valid manual password from the user
def get_valid_manual_password() -> str:
    while True:
        password = getpass.getpass("Enter your desired password (12-60 characters): ")
        if 12 <= len(password) <= 60:
            return password
        else:
            print("Error: Password length must be between 12 and 60 characters.")

# Function to create a new user account
def create_account():
    username = input("Enter your desired username: ")
    
    # Check if username already exists
    if username in password_manager:
        print("Error: Username already exists.")
        return

    # Ask the user if they want to generate a password
    use_generated_password = input("Do you want to generate a secure password? (y/n): ").lower().strip()
    
    if use_generated_password == 'y':
        password_length = get_password_length()
        password = generate_password(password_length)
        print(f"Generated Password: {password}")
        print(f"IMPORTANT!!! Make sure to save your generated password, it will not be shown again for security reasons.")
    else:
        password = get_valid_manual_password()
    
    hashed_password = hash_password(password)
    password_manager[username] = hashed_password
    print("Account created successfully!")

    # Save the updated password manager to the file
    save_passwords_to_file()

# Function to authenticate a user
def authenticate_user(username: str, password: str) -> bool:
    hashed_password = hash_password(password)
    return username in password_manager and password_manager[username] == hashed_password

# Function to log in a user
def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    if authenticate_user(username, password):
        print("Login successful!")
    else:
        print("Invalid username or password.")

# Function to load passwords from a file
def load_passwords_from_file(filename: str):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            for line in file:
                username, hashed_password = line.strip().split(':')
                password_manager[username] = hashed_password
        print(f"Loaded {len(password_manager)} accounts from {filename}.")
    else:
        print(f"No existing data found. Starting fresh.")

# Function to save passwords to a file
def save_passwords_to_file(filename: str = "passwords.txt"):
    with open(filename, 'w') as file:
        for username, hashed_password in password_manager.items():
            file.write(f"{username}:{hashed_password}\n")
    print(f"Passwords saved to '{filename}' successfully!")

# Improved main menu loop
def main():
    load_passwords_from_file("passwords.txt")  # Load existing passwords at startup
    
    while True:
        print("\nMenu:\n1: Create account\n2: Login\n3: Export passwords to file\n0: Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            create_account()  # Call to create an account
        elif choice == "2":
            login()  # Call to log in
        elif choice == "3":
            save_passwords_to_file()  # Call to export passwords
        elif choice == "0":
            exit_program()  # Call to exit
        else:
            print("Invalid choice. Please select 1, 2, 3, or 0.")

# Function to exit the program
def exit_program():
    print("Exiting program.")
    save_passwords_to_file()  # Save before exiting
    exit()

if __name__ == "__main__":
    main()