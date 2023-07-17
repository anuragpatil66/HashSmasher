# Done by Anurag Patil - https://www.linkedin.com/in/anurag-patil-2a9b0022a/

import hashlib  # Importing the hashlib module for cryptographic hash functions
import os  # Importing the os module for file operations
import bcrypt  # Importing the bcrypt module for password hashing

"""
hash_password(password, algorithm):

a)This function takes a password and an algorithm as input.
b)It hashes the password using the specified algorithm.
c)If the algorithm is MD5, it uses the hashlib.md5() function to compute the MD5 hash of the password and returns the hexadecimal representation of the hash.
d)If the algorithm is SHA-512, it uses the hashlib.sha512() function to compute the SHA-512 hash of the password and returns the hexadecimal representation of the hash.
e)If the algorithm is bcrypt, it uses the bcrypt.hashpw() function from the bcrypt library to hash the password using bcrypt with a randomly generated salt. The resulting hash is then decoded to a string before returning.
f)If the algorithm is not recognized, it prints an error message and returns None.
The function returns the hashed password
"""
def hash_password(password, algorithm):
# Function to hash a password using the specified algorithm
    if algorithm == "md5":  # If the algorithm is MD5
        hashed_password = hashlib.md5(password.encode()).hexdigest()  # Hash the password using MD5 algorithm
    elif algorithm == "sha512":  # If the algorithm is SHA-512
        hashed_password = hashlib.sha512(password.encode()).hexdigest()  # Hash the password using SHA-512 algorithm
    elif algorithm == "bcrypt":  # If the algorithm is bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Hash the password using bcrypt algorithm
    else:  # If the algorithm is not recognized
        print("Invalid hashing algorithm.")
        return None
    return hashed_password  # Return the hashed password

"""
crack_hash(target_hash, passwords, algorithm):

a)This function attempts to crack a given target hash using a list of passwords and the specified hashing algorithm.
b)It iterates over each password in the passwords list.
c)Depending on the algorithm, it hashes each password using the corresponding algorithm.
d)If the algorithm is MD5, it computes the MD5 hash of the password.
e)If the algorithm is SHA-512, it computes the SHA-512 hash of the password.
f)If the algorithm is bcrypt, it hashes the password using bcrypt and the target hash as the salt.
g)If the hashed password matches the target hash, it returns the cracked password.
h)If no match is found, it returns None.
"""
def crack_hash(target_hash, passwords, algorithm):
# Function to crack a hash given a list of passwords and the hashing algorithm
    for password in passwords:  # Iterate over each password in the list
        if algorithm == "md5":  # If the algorithm is MD5
            hashed_password = hashlib.md5(password.encode()).hexdigest()  # Hash the password using MD5 algorithm
        elif algorithm == "sha512":  # If the algorithm is SHA-512
            hashed_password = hashlib.sha512(password.encode()).hexdigest()  # Hash the password using SHA-512 algorithm
        elif algorithm == "bcrypt":  # If the algorithm is bcrypt
            hashed_password = bcrypt.hashpw(password.encode(), target_hash.encode()).decode()  # Hash the password using bcrypt algorithm and the given target hash
        else:  # If the algorithm is not recognized
            print("Invalid hashing algorithm.")
            return None

        if hashed_password == target_hash:  # If the hashed password matches the target hash
            return password  # Return the cracked password
    return None  # Return None if the password cannot be cracked

"""
validate_hash(target_hash, algorithm):

a)This function validates the length of a target hash based on the specified hashing algorithm.
b)It takes the target hash and the algorithm as input.
c)If the algorithm is MD5 and the length of the target hash is not 32 characters, it returns False indicating an invalid hash.
d)If the algorithm is SHA-512 and the length of the target hash is not 128 characters, it returns False indicating an invalid hash.
e)If the algorithm is bcrypt and the length of the target hash is not 60 characters, it returns False indicating an invalid hash.
f)If the length of the target hash matches the expected length for the algorithm, it returns True indicating a valid hash.
"""
def validate_hash(target_hash, algorithm):
# Function to validate the length of a target hash based on the hashing algorithm
    if algorithm == "md5" and len(target_hash) != 32:  # If the algorithm is MD5 and the hash length is not 32 characters
        return False  # Return False indicating invalid hash
    elif algorithm == "sha512" and len(target_hash) != 128:  # If the algorithm is SHA-512 and the hash length is not 128 characters
        return False  # Return False indicating invalid hash
    elif algorithm == "bcrypt" and len(target_hash) != 60:  # If the algorithm is bcrypt and the hash length is not 60 characters
        return False  # Return False indicating invalid hash
    return True  # Return True if the hash is valid

"""
validate_file_path(file_path):

a)This function validates a file path and checks if it is a valid text file.
b)It takes a file path as input.
c)It checks if the file path exists as a file (os.path.isfile(file_path)) and if it has a .txt extension (file_path.lower().endswith(".txt")).
d)If both conditions are satisfied, it returns True, indicating a valid file path.
e)Otherwise, it returns False, indicating an invalid file path.
"""
def validate_file_path(file_path):
# Function to validate a file path and check if it is a valid text file
    if os.path.isfile(file_path) and file_path.lower().endswith(".txt"):  # If the file path exists and has a .txt extension
        return True  # Return True indicating valid file path
    return False  # Return False indicating invalid file path

"""
get_passwords_input():

a)This function prompts the user to choose how to provide passwords.
b)It handles user input and returns a list of passwords based on the chosen method.
c)It uses a while loop to repeat until a valid choice is made.
d)The function displays a menu with options for the user to choose from:
    i)Enter passwords separated by commas
    ii)Provide a path to a text file containing passwords
    iii)Return to the previous menu
    iv)Exit the program
e)Depending on the user's choice, the function:
    i)For choice 1: prompts the user to enter passwords separated by commas and stores them in a list.
    ii)For choice 2: prompts the user to enter the path to a text file containing passwords, validates the file path, reads the passwords from the file, and stores them in a list.
    iii)For choice 3: returns None to indicate going back to the previous menu.
    iv)For choice 4: displays a farewell message and exits the program.
f)The function returns the list of passwords or None based on the user's choice.
"""
def get_passwords_input():
# Function to get input for passwords from the user
    while True:  # Repeat until a valid choice is made
        print("\n---Choose how to provide passwords---")
        print("1. Enter passwords separated by commas")
        print("2. Provide a path to a text (.txt) file containing passwords (Ex: X:\\Path\\Path\\anything.txt): ")
        print("3. Return to previous menu")
        print("4. Exit")
        choice = input("Enter your choice (1, 2, 3, or 4): ")  # Get user's choice

        passwords = []  # Initialize an empty list for passwords

        if choice == "1":  # If the choice is 1 (Enter passwords separated by commas)
            passwords_input = input("Enter passwords separated by commas: ")  # Prompt the user to enter passwords
            passwords = passwords_input.split(",")  # Split the input by commas and store passwords in the list
            break  # Break out of the loop

        elif choice == "2":  # If the choice is 2 (Provide a path to a text file)
            while True:  # Repeat until a valid file path is provided
                print()
                file_path = input("Enter the path to the text file (.txt) containing passwords (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the file path
                if os.path.isdir(os.path.dirname(file_path)):  # Check if the directory of the file path exists
                    if validate_file_path(file_path):  # Check if the file path is valid and has a .txt extension
                        try:
                            with open(file_path, "r") as file:  # Open the file in read mode
                                passwords = [line.strip() for line in file]  # Read each line, remove leading/trailing whitespace, and store passwords in the list
                            break  # Break out of the loop
                        except FileNotFoundError:  # If the file is not found
                            print("File not found. Please try again.")
                    else:
                        print("Invalid file path or file format. Please provide a valid .txt file.")
                else:
                    print("Invalid file path. Please try again.")
            break  # Break out of the loop

        elif choice == "3":  # If the choice is 3 (Return to previous menu)
            return None

        elif choice == "4":  # If the choice is 4 (Exit)
            print("Thank You For Using HashSmasher!!!")
            exit()

        else:  # If the choice is invalid
            print("Invalid choice. Please try again.")

    return passwords  # Return the list of passwords based on the user's choice

"""
hash_passwords_from_file(file_path, algorithm):

a)This function hashes passwords from a text file using the specified algorithm.
b)It opens the file in read mode and reads each line, removing leading/trailing whitespace, and storing the passwords in a list.
c)It iterates over each password in the list and hashes it using the specified algorithm by calling the hash_password() function.
d)The hashed passwords are stored in a separate list.
f)The function returns the list of hashed passwords or None if the file is not found.
"""
def hash_passwords_from_file(file_path, algorithm):
# Function to hash passwords from a file using the specified algorithm
    try:
        with open(file_path, "r") as file:  # Open the file in read mode
            passwords = [line.strip() for line in file]  # Read each line, remove leading/trailing whitespace, and store passwords in a list
            hashed_passwords = []  # Initialize an empty list to store hashed passwords
            for password in passwords:  # Iterate over each password in the list
                hashed_password = hash_password(password, algorithm)  # Hash the password using the specified algorithm
                hashed_passwords.append(hashed_password)  # Add the hashed password to the list
            return hashed_passwords  # Return the list of hashed passwords
    except FileNotFoundError:  # If the file is not found
        print("File not found. Please try again.")
        return None

"""
crack_hash_from_file(file_path, passwords, algorithm):

a)This function attempts to crack password hashes from a text file using a list of passwords and the specified algorithm.
b)It opens the file in read mode and reads the first line, which contains the target hash.
c)While there are more lines in the file, the function performs the following steps:
    i)It checks if the target hash is valid for the specified algorithm by calling the validate_hash() function.
    ii)If the target hash is valid, it attempts to crack the target hash using the crack_hash() function and the provided list of passwords.
    iii)If a password is cracked, it yields a tuple containing the target hash and the cracked password.
    iv)If the password cannot be cracked, it yields a tuple containing the target hash and a failure message.
    v)It reads the next target hash from the file.
d)The function uses a generator to yield the target hash and cracked password for each line in the file.
e)If the file is not found, it prints an error message and returns None
"""
def crack_hash_from_file(file_path, passwords, algorithm):
# Function to crack password hashes from a file using a list of passwords and the specified algorithm
    try:
        with open(file_path, "r") as file:  # Open the file in read mode
            target_hash = file.readline().strip()  # Read the first line, which contains the target hash
            while target_hash:  # Continue until the end of the file
                if validate_hash(target_hash, algorithm):  # Check if the target hash is valid for the specified algorithm
                    cracked_password = crack_hash(target_hash, passwords, algorithm)  # Attempt to crack the target hash using the list of passwords
                    if cracked_password:  # If a password is cracked
                        yield target_hash, cracked_password  # Yield the target hash and cracked password
                    else:  # If the password cannot be cracked
                        yield target_hash, "Password Not In The List You Provided Hence The Hash Could Not Be Cracked"  # Yield the target hash and a message indicating failure
                else:  # If the target hash is invalid for the algorithm
                    print(f"Invalid target hash for chosen algorithm ({algorithm.upper()}): {target_hash}")
                target_hash = file.readline().strip()  # Read the next target hash from the file
    except FileNotFoundError:  # If the file is not found
        print("File not found. Please try again.")

"""
save_result(file_path, passwords, algorithm, is_cracked=True):

a)This function saves the result (hashed passwords or cracked hashes) to a text file.
b)It prompts the user to enter the path to save the result in a text file.
c)It checks if the directory of the save file path exists and if the save file path has a .txt extension.
d)If both conditions are satisfied, it opens the save file in write mode.
e)If the result is cracked hashes (default), it iterates over the cracked hashes and passwords obtained from calling crack_hash_from_file().
f)For each cracked hash and password, it writes the target hash, cracked password, and a blank line for separation in the save file.
g)If the result is hashed passwords, it calls hash_passwords_from_file() to hash the passwords from the file and writes each hashed password to the save file.
h)If the file is not found, it prints an error message.
i)The function uses a while loop to repeat until a valid file path is provided.
"""
def save_result(file_path, passwords, algorithm, is_cracked=True):
# Function to save the result (hashed passwords or cracked hashes) to a file
    while True:  # Repeat until a valid file path is provided
        print()
        save_file_path = input("Enter the path to save the result in a text file (.txt) (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the save file path
        if os.path.isdir(os.path.dirname(save_file_path)):  # Check if the directory of the save file path exists
            if save_file_path.lower().endswith(".txt"):  # Check if the save file path has a .txt extension
                try:
                    with open(save_file_path, "w") as save_file:  # Open the save file in write mode
                        if is_cracked:  # If the result is cracked hashes
                            for target_hash, password in crack_hash_from_file(file_path, passwords, algorithm):  # Iterate over the cracked hashes and passwords
                                save_file.write(f"Target Hash: {target_hash}\n")  # Write the target hash to the save file
                                save_file.write(f"Cracked Password: {password}\n")  # Write the cracked password to the save file
                                save_file.write("\n")  # Write a blank line for separation
                        else:  # If the result is hashed passwords
                            hashed_passwords = hash_passwords_from_file(file_path, algorithm)  # Hash the passwords from the file
                            if hashed_passwords:  # If hashed passwords are obtained
                                for hashed_password in hashed_passwords:  # Iterate over the hashed passwords
                                    save_file.write(f"{hashed_password}\n")  # Write each hashed password to the save file
                except FileNotFoundError:  # If the file is not found
                    print("File not found. Please try again.")
                break  # Break out of the loop
            else:  # If the save file path is invalid or does not have a .txt extension
                print("Invalid file path or file format. Please provide a valid .txt file.")
        else:  # If the directory of the save file path does not exist
            print("Invalid file path. Please try again.")

"""
main():

a)This is the main function that runs the HashSmasher tool.
b)It uses a while loop to repeat until a valid choice is made.
c)The function displays a menu with options for the user to choose from:
    i)Hash a password
    ii)Crack a hash
    iii)Exit the program
d)Depending on the user's choice, the function:
    i)For choice 1: prompts the user to choose the hashing algorithm (MD5, SHA-512, or BCrypt) and the hashing option (hash a single password or hash passwords from a text file). It calls the respective functions to perform the chosen operation.
    iii)For choice 2: prompts the user to choose the cracking algorithm (MD5, SHA-512, or BCrypt) and the cracking option (crack hash from a text file or crack a single hash). It calls the respective functions to perform the chosen operation.
    iv)For choice 3: displays a farewell message and breaks out of the loop, terminating the program.
e)The main() function is responsible for driving the flow of the HashSmasher tool.
"""
def main():
    # Main function to run the HashSmasher tool
    print("\n", "Welcome to HashSmasher - An all-in-one tool for password hashing and hash cracking using custom password lists, supporting multiple algorithms (MD5, SHA-512, BCrypt).")
    print("------------------------------------------------------------------------------------------------------------------------------------------------------")

    while True:  # Repeat until a valid choice is made
        print("\n--- Menu ---")
        print("1. Hash a password")
        print("2. Crack a hash")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")  # Get user's choice

        if choice == "1":  # If the choice is 1 (Hash a password)
            while True:  # Repeat until a valid choice is made
                print("\n--- Hash a Password ---")
                print("1. MD5")
                print("2. SHA-512")
                print("3. Bcrypt")
                print("4. Return to main menu")
                print("5. Exit")
                algorithm_choice = input("Enter your choice (1, 2, 3, 4, or 5): ")  # Get user's choice for the hashing algorithm

                if algorithm_choice == "1":  # If the algorithm choice is 1 (MD5)
                    while True:  # Repeat until a valid choice is made
                        print("\n--- Choose Hashing Option ---")
                        print("1. Hash a single password")
                        print("2. Hash passwords from a text file")
                        print("3. Return to previous menu")
                        print("4. Exit")
                        option_choice = input("Enter your choice (1, 2, 3, or 4): ")  # Get user's choice for the hashing option

                        if option_choice == "1":  # If the option choice is 1 (Hash a single password)
                            print()
                            password = input("Enter a password: ")  # Prompt the user to enter a password
                            hashed_password = hash_password(password, "md5")  # Hash the password using MD5 algorithm
                            print("Hashed password (MD5):", hashed_password)  # Print the hashed password
                            break

                        elif option_choice == "2":  # If the option choice is 2 (Hash passwords from a text file)
                            while True:  # Repeat until a valid file path is provided
                                print()
                                file_path = input("Enter the path to the text file (.txt) containing passwords needed to hash (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the file path
                                if os.path.isdir(os.path.dirname(file_path)):  # Check if the directory of the file path exists
                                    if validate_file_path(file_path):  # Check if the file path is valid and has a .txt extension
                                        save_result(file_path, [], "md5", is_cracked=False)  # Save the hashed passwords to a file
                                        break
                                    else:
                                        print("Invalid file path or file format. Please provide a valid .txt file.")
                                else:
                                    print("Invalid file path. Please try again.")
                            break

                        elif option_choice == "3":  # If the option choice is 3 (Return to previous menu)
                            break

                        elif option_choice == "4":  # If the option choice is 4 (Exit)
                            print("Thank You For Using HashSmasher!!!")
                            exit()

                        else:  # If an invalid choice is made
                            print("Invalid choice. Please try again.")

                elif algorithm_choice == "2":  # If the algorithm choice is 2 (SHA-512)
                    while True:  # Repeat until a valid choice is made
                        print("\n--- Choose Hashing Option ---")
                        print("1. Hash a single password")
                        print("2. Hash passwords from a text file")
                        print("3. Return to previous menu")
                        print("4. Exit")
                        option_choice = input("Enter your choice (1, 2, 3, or 4): ")  # Get user's choice for the hashing option

                        if option_choice == "1":  # If the option choice is 1 (Hash a single password)
                            print()
                            password = input("Enter a password: ")  # Prompt the user to enter a password
                            hashed_password = hash_password(password, "sha512")  # Hash the password using SHA-512 algorithm
                            print("Hashed password (SHA-512):", hashed_password)  # Print the hashed password
                            break

                        elif option_choice == "2":  # If the option choice is 2 (Hash passwords from a text file)
                            while True:  # Repeat until a valid file path is provided
                                print()
                                file_path = input("Enter the path to the text file (.txt) containing passwords needed to hash (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the file path
                                if os.path.isdir(os.path.dirname(file_path)):  # Check if the directory of the file path exists
                                    if validate_file_path(file_path):  # Check if the file path is valid and has a .txt extension
                                        save_result(file_path, [], "sha512", is_cracked=False)  # Save the hashed passwords to a file
                                        break
                                    else:
                                        print("Invalid file path or file format. Please provide a valid .txt file.")
                                else:
                                    print("Invalid file path. Please try again.")
                            break

                        elif option_choice == "3":  # If the option choice is 3 (Return to previous menu)
                            break

                        elif option_choice == "4":  # If the option choice is 4 (Exit)
                            print("Thank You For Using HashSmasher!!!")
                            exit()

                        else:  # If an invalid choice is made
                            print("Invalid choice. Please try again.")

                elif algorithm_choice == "3":  # If the algorithm choice is 3 (BCrypt)
                    while True:  # Repeat until a valid choice is made
                        print("\n--- Choose Hashing Option ---")
                        print("1. Hash a single password")
                        print("2. Hash passwords from a text file")
                        print("3. Return to previous menu")
                        print("4. Exit")
                        option_choice = input("Enter your choice (1, 2, 3, or 4): ")  # Get user's choice for the hashing option

                        if option_choice == "1":  # If the option choice is 1 (Hash a single password)
                            print()
                            password = input("Enter a password: ")  # Prompt the user to enter a password
                            hashed_password = hash_password(password, "bcrypt")  # Hash the password using BCrypt algorithm
                            print("Hashed password (BCrypt):", hashed_password)  # Print the hashed password
                            break

                        elif option_choice == "2":  # If the option choice is 2 (Hash passwords from a text file)
                            while True:  # Repeat until a valid file path is provided
                                print()
                                file_path = input("Enter the path to the text file (.txt) containing passwords needed to hash (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the file path
                                if os.path.isdir(os.path.dirname(file_path)):  # Check if the directory of the file path exists
                                    if validate_file_path(file_path):  # Check if the file path is valid and has a .txt extension
                                        save_result(file_path, [], "bcrypt", is_cracked=False)  # Save the hashed passwords to a file
                                        break
                                    else:
                                        print("Invalid file path or file format. Please provide a valid .txt file.")
                                else:
                                    print("Invalid file path. Please try again.")
                            break

                        elif option_choice == "3":  # If the option choice is 3 (Return to previous menu)
                            break

                        elif option_choice == "4":  # If the option choice is 4 (Exit)
                            print("Thank You For Using HashSmasher!!!")
                            exit()

                        else:  # If an invalid choice is made
                            print("Invalid choice. Please try again.")

                elif algorithm_choice == "4":  # If the algorithm choice is 4 (Return to main menu)
                    break

                elif algorithm_choice == "5":  # If the algorithm choice is 5 (Exit)
                    print("Thank You For Using HashSmasher!!!")
                    exit()

                else:  # If an invalid choice is made
                    print("Invalid choice. Please try again.")

        elif choice == "2":  # If the choice is 2 (Crack a hash)
            while True:  # Repeat until a valid choice is made
                print("\n--- Crack a Hash ---")
                print("1. MD5")
                print("2. SHA-512")
                print("3. BCrypt")
                print("4. Return to main menu")
                print("5. Exit")
                algorithm_choice = input("Enter your choice (1, 2, 3, 4, or 5): ")  # Get user's choice for the cracking algorithm

                if algorithm_choice == "1":  # If the algorithm choice is 1 (MD5)
                    algorithm = "md5"
                elif algorithm_choice == "2":  # If the algorithm choice is 2 (SHA-512)
                    algorithm = "sha512"
                elif algorithm_choice == "3":  # If the algorithm choice is 3 (BCrypt)
                    algorithm = "bcrypt"
                elif algorithm_choice == "4":  # If the algorithm choice is 4 (Return to main menu)
                    break
                elif algorithm_choice == "5":  # If the algorithm choice is 5 (Exit)
                    print("Thank You For Using HashSmasher!!!")
                    exit()
                else:  # If an invalid choice is made
                    print("Invalid choice. Please try again.")
                    continue

                while True:  # Repeat until a valid choice is made
                    print("\n--- Crack Hash Options ---")
                    print("1. Crack hash from a text file")
                    print("2. Crack a single hash")
                    print("3. Return to previous menu")
                    print("4. Exit")
                    crack_option = input("Enter your choice (1, 2, 3, or 4): ")  # Get user's choice for the cracking option

                    if crack_option == "1":  # If the crack option is 1 (Crack hash from a text file)
                        while True:  # Repeat until a valid file path is provided
                            print()
                            file_path = input("Enter the path to the text file (.txt) containing hashes (Ex: X:\\Path\\Path\\anything.txt): ")  # Prompt the user to enter the file path
                            if os.path.isdir(os.path.dirname(file_path)):  # Check if the directory of the file path exists
                                if validate_file_path(file_path):  # Check if the file path is valid and has a .txt extension
                                    passwords = get_passwords_input()  # Get the list of passwords from the user
                                    if passwords is None:  # If the user chooses to return to the previous menu
                                        break
                                    if passwords:  # If passwords are provided
                                        save_result(file_path, passwords, algorithm)  # Save the cracked passwords to a file
                                    break
                                else:
                                    print("Invalid file path or file format. Please provide a valid .txt file.")
                            else:
                                print("Invalid file path. Please try again.")
                        break

                    elif crack_option == "2":  # If the crack option is 2 (Crack a single hash)
                        while True:  # Repeat until a valid target hash is provided
                            print()
                            target_hash = input("Enter the target hash: ")  # Prompt the user to enter the target hash
                            if not validate_hash(target_hash, algorithm):  # If the target hash is invalid for the algorithm
                                if algorithm == "md5":
                                    print(f"Error: Mismatch between chosen algorithm ({algorithm.upper()}) and target hash. Only provide MD5 hash.")
                                elif algorithm == "sha512":
                                    print(f"Error: Mismatch between chosen algorithm ({algorithm.upper()}) and target hash. Only provide SHA-512 hash.")
                                elif algorithm == "bcrypt":
                                    print(f"Error: Mismatch between chosen algorithm ({algorithm.upper()}) and target hash. Only provide BCrypt hash.")
                            else:
                                break

                        while True:  # Repeat until valid passwords are provided or user chooses to return to the previous menu
                            passwords = get_passwords_input()  # Get the list of passwords from the user
                            if passwords is None:  # If the user chooses to return to the previous menu
                                break
                            if passwords:  # If passwords are provided
                                break

                        if passwords is None:  # If the user chooses to return to the previous menu
                            break

                        cracked_password = crack_hash(target_hash, passwords, algorithm)  # Crack the target hash using the list of passwords
                        if cracked_password:  # If a password is cracked
                            print("Password cracked! The password is:", cracked_password)  # Print the cracked password
                        else:  # If the password is not found
                            print("Password not found.")
                        break

                    elif crack_option == "3":  # If the crack option is 3 (Return to previous menu)
                        break

                    elif crack_option == "4":  # If the crack option is 4 (Exit)
                        print("Thank You For Using HashSmasher!!!")
                        exit()

                    else:  # If an invalid choice is made
                        print("Invalid choice. Please try again.")

        elif choice == "3":  # If the choice is 3 (Exit)
            print("Thank You For Using HashSmasher!!!")
            break

        else:  # If an invalid choice is made
            print("Invalid choice. Please try again.")

"""
The code checks if the script is being run directly (as the main module) or if it is being imported by another module.

a)If the script is being run directly, the condition __name__ == '__main__' evaluates to True, and the code proceeds to call the main function.
b)If the script is being imported by another module, the condition __name__ == '__main__' evaluates to False, and the main function is not executed. This prevents the script's code from running if it is imported as a module, allowing it to be used as a library or component in another program.
"""
if __name__ == "__main__":
    main()
