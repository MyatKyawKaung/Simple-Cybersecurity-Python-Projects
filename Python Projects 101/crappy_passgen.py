import secrets
import string

# Function to generate a random password
def generate_password(length: int):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Function to get user input for password length with validation
def get_password_length():
    while True:
        try:
            length = int(input("Enter your desired password length (12-60): "))
            if 12 <= length <= 60:
                return length
            else:
                print("Error: Password length must be between 12 and 60 characters.")
        except ValueError:
            print("Error: Please enter a valid integer.")

# Get the password length from the user
password_length = get_password_length()

# Generate and display the password
password = generate_password(password_length)
print(f"Generated Password: {password}")