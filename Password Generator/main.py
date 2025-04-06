import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import string
import secrets
import pyperclip
import re

def generate_password():
    length = password_length.get()
    password_type = password_type_var.get()  # Get selected password type

    # Default length for Passphrase if none is provided
    if password_type == "Passphrase" and not length:
        length = 2  # Default to 2 words for the passphrase (each word 5 characters long)
    
    # Default length for API Key if none is provided
    if password_type == "API Key" and not length:
        length = 32  # Default to 32 characters for API Key

    try:
        length = int(length)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for length.")
        return

    # Character selection based on password type
    if password_type == "Standard Password":
        char_pool = ""
        use_lowercase = lowercase.get()
        use_uppercase = uppercase.get()
        use_digits = digits.get()
        use_special = special.get()

        if length < 4:
            messagebox.showerror("Error", "Password length must be at least 4 characters")
            return
        
        if use_lowercase:
            char_pool += string.ascii_lowercase
        if use_uppercase:
            char_pool += string.ascii_uppercase
        if use_digits:
            char_pool += string.digits
        if use_special:
            char_pool += string.punctuation
        if not char_pool:
            messagebox.showerror("Error", "Choose at least one character type.")
            return
        
    elif password_type == "Passphrase":
        # Generate passphrase with random words (5 characters per word)
        passphrase = "-".join(generate_random_word(5) for _ in range(length))
        password_display.config(state=tk.NORMAL)
        password_display.delete(0, tk.END)
        password_display.insert(0, passphrase)
        password_display.config(state=tk.DISABLED)
        evaluate_strength(passphrase)
        return

    elif password_type == "PIN":
        # Generate a PIN (numerical only)
        char_pool = string.digits
        # No strength evaluation for PIN
        password = ''.join(secrets.choice(char_pool) for _ in range(length))
        password_display.config(state=tk.NORMAL)
        password_display.delete(0, tk.END)
        password_display.insert(0, password)
        password_display.config(state=tk.DISABLED)
        return

    elif password_type == "API Key":
        # API Key with alphanumeric + special characters (32 characters)
        char_pool = string.ascii_letters + string.digits + string.punctuation
        length = 32  # Ensure the API key is always 32 characters long

    password = ""
    for _ in range(length):
        password += secrets.choice(char_pool)
        
    password_display.config(state=tk.NORMAL)
    password_display.delete(0, tk.END)
    password_display.insert(0, password)
    password_display.config(state=tk.DISABLED)
    
    evaluate_strength(password)

def generate_random_word(length):
    # Generate a random word of the specified length
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))

def evaluate_strength(password):
    # Check the basic length first
    if len(password) < 8:
        strength = "Weak"
        color = "red"
    else:
        # Check if the password contains at least one lowercase, one uppercase, one digit, and one special character
        has_lower = re.search(r'[a-z]', password)
        has_upper = re.search(r'[A-Z]', password)
        has_digit = re.search(r'[0-9]', password)
        has_special = re.search(r'[{}()!@#$%^&*()_+|:;,.<>?/\-=`~]', password)

        # If all character types are present and the length is at least 12, consider it strong
        if has_lower and has_upper and has_digit and has_special:
            if len(password) >= 12:
                strength = "Strong"
                color = "green"
            else:
                strength = "Medium"
                color = "orange"
        else:
            # If it doesn't meet the criteria for a strong password
            strength = "Medium"
            color = "orange"

    strength_label.config(text=f"Strength: {strength}", fg=color)

def copy_password():
    password = password_display.get()
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

root = tk.Tk()
root.title("CipherCraft")
root.geometry("400x400")

# Label for Password Type
password_type_label = tk.Label(root, text="Password Type:")
password_type_label.grid(row=0, column=0, padx=10, pady=5)

# Combobox for selecting password type
password_type_var = tk.StringVar(value="Standard Password")
password_type_menu = ttk.Combobox(root, textvariable=password_type_var, values=["Standard Password", "Passphrase", "PIN", "API Key"])
password_type_menu.grid(row=0, column=1, padx=10, pady=5)

# Label for Password Length
password_length_label = tk.Label(root, text="Set Length:")
password_length_label.grid(row=1, column=0, padx=10, pady=5)

# Entry for Password Length
password_length = tk.Entry(root)
password_length.grid(row=1, column=1, padx=10, pady=5)

# Checkbox for character options
lowercase = tk.BooleanVar()
uppercase = tk.BooleanVar()
digits = tk.BooleanVar()
special = tk.BooleanVar()

lowercase_checkbox = tk.Checkbutton(root, text="Lowercase Letters", variable=lowercase)
lowercase_checkbox.grid(row=2, column=0, padx=10, pady=5)

uppercase_checkbox = tk.Checkbutton(root, text="Uppercase Letters", variable=uppercase)
uppercase_checkbox.grid(row=3, column=0, padx=10, pady=5)

digit_checkbox = tk.Checkbutton(root, text="Digits", variable=digits)
digit_checkbox.grid(row=4, column=0, padx=10, pady=5)

special_checkbox = tk.Checkbutton(root, text="Special Characters", variable=special)
special_checkbox.grid(row=5, column=0, padx=10, pady=5)

# Generate Button
generate_button = tk.Button(root, text="Generate", command=generate_password)
generate_button.grid(row=6, column=0, columnspan=2, pady=10)

# Password Display Field
password_display = tk.Entry(root, width=40, state=tk.DISABLED)
password_display.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

# Strength Label
strength_label = tk.Label(root, text="Strength: ", font=("Helvetica", 10))
strength_label.grid(row=8, column=0, columnspan=2)

# Copy to Clipboard Button
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_password)
copy_button.grid(row=9, column=0, columnspan=2, pady=10)

root.mainloop()
