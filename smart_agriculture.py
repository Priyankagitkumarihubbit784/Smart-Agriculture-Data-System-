import sqlite3
from tkinter import *
from tkinter import messagebox
import hashlib  # For password hashing

# Database Setup 
conn = sqlite3.connect('agriculture.db')
cursor = conn.cursor()

# Users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# Crops table
cursor.execute('''
CREATE TABLE IF NOT EXISTS crops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    soil_type TEXT,
    water_need TEXT
)
''')

# User selections table
cursor.execute('''
CREATE TABLE IF NOT EXISTS user_selection (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    soil_type TEXT,
    water_level TEXT,
    recommended_crop TEXT
)
''')

# Insert sample crops if empty
cursor.execute("SELECT COUNT(*) FROM crops")
if cursor.fetchone()[0] == 0:
    crops = [
        ('Rice', 'Loamy', 'High'),
        ('Wheat', 'Clay', 'Medium'),
        ('Millet', 'Sandy', 'Low'),
        ('Maize', 'Loamy', 'Medium'),
        ('Barley', 'Clay', 'Medium'),
        ('Sorghum', 'Sandy', 'Low'),
        ('Sugarcane', 'Loamy', 'High'),
        ('Soybean', 'Loamy', 'Medium'),
        ('Tomato', 'Sandy', 'Medium'),
        ('Potato', 'Clay', 'High'),
        ('Onion', 'Loamy', 'Medium'),
        ('Pea', 'Sandy', 'Low'),
        ('Cotton', 'Sandy', 'Medium'),
        ('Sunflower', 'Loamy', 'Medium'),
        ('Banana', 'Loamy', 'High')
    ]
    cursor.executemany('INSERT INTO crops (name, soil_type, water_need) VALUES (?, ?, ?)', crops)
    conn.commit()

# Crop Recommendation Window
def open_main_window(username):
    main = Tk()
    main.title("Smart Agriculture Data System")
    main.geometry("600x600")
    main.config(bg="#e6ffe6")
    main.resizable(False, False)

    Label(main, text=f"Welcome, {username}", font=("Arial", 14, "italic"), bg="#e6ffe6", fg="#333").pack(pady=15)
    Label(main, text="🌾 Smart Agriculture Data System 🌾", font=("Arial", 16, "bold"), bg="#e6ffe6", fg="#006400").pack(pady=15)

    Label(main, text="Select Soil Type:", font=("Arial", 12), bg="#e6ffe6").pack(pady=5)
    soil_var = StringVar()
    OptionMenu(main, soil_var, "Loamy", "Clay", "Sandy").pack(pady=10)

    Label(main, text="Select Water Level:", font=("Arial", 12), bg="#e6ffe6").pack(pady=5)
    water_var = StringVar()
    OptionMenu(main, water_var, "High", "Medium", "Low").pack(pady=10)

    # Recommendation Function
    def recommend_crop():
        soil = soil_var.get()
        water = water_var.get()
        if soil == "" or water == "":
            messagebox.showwarning("Input Error", "Please select both options.")
            return

        cursor.execute("SELECT name, soil_type, water_need FROM crops")
        crops_data = cursor.fetchall()
        recommended = []

        for crop in crops_data:
            if crop[1].lower() == soil.lower() and crop[2].lower() == water.lower():
                recommended.append(crop[0])

        if recommended:
            recommended_text = ', '.join(recommended)
            result_text = f"You selected:\nSoil Type: {soil}\nWater Level: {water}\n\nRecommended Crop(s): {recommended_text}"
        else:
            recommended_text = None
            result_text = f"You selected:\nSoil Type: {soil}\nWater Level: {water}\n\nNo suitable crop found."

        # Save the user selection in database (for developer use)
        cursor.execute('''
            INSERT INTO user_selection (username, soil_type, water_level, recommended_crop)
            VALUES (?, ?, ?, ?)
        ''', (username, soil, water, recommended_text))
        conn.commit()

        # Display the selection and recommendation in the window
        if hasattr(main, 'result_label'):
            main.result_label.config(text=result_text)
        else:
            main.result_label = Label(main, text=result_text, font=("Arial", 12), bg="#e6ffe6", justify=LEFT)
            main.result_label.pack(pady=15)

    #Buttons
    Button(main, text="Get Recommendation", font=("Arial", 13), command=recommend_crop,
           bg="#4CAF50", fg="white", padx=10, pady=10).pack(pady=15)

    Button(main, text="Exit", font=("Arial", 12), command=main.destroy,
           bg="red", fg="white", padx=10, pady=10).pack(pady=10)

    main.mainloop()

#Registration
def register_user():
    username = reg_user.get().strip()
    password = reg_pass.get().strip()
    if username == "" or password == "":
        messagebox.showwarning("Input Error", "All fields are required.")
        return

    # Hash the password before storing
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        messagebox.showinfo("Info", "User already registered. Please login.")
        reg_window.destroy()
        login_user_window()
        return

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    messagebox.showinfo("Success", "Registration successful! Now login.")
    reg_window.destroy()
    login_user_window()

#Login
def login_user():
    username = login_user_var.get().strip()
    password = login_pass_var.get().strip()

    # Hash the password entered
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    if user:
        messagebox.showinfo("Login Success", f"Welcome, {username}!")
        login_window.destroy()
        open_main_window(username)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

#GUI Windows
def register_window_func():
    global reg_window, reg_user, reg_pass, password_entry, toggle_button
    reg_window = Tk()
    reg_window.title("Register")
    reg_window.geometry("500x350")
    reg_window.config(bg="#d9f9d9")
    reg_window.resizable(False, False)

    Label(reg_window, text="Register New User", font=("Arial", 16, "bold"), bg="#d9f9d9", fg="#006400").pack(pady=15)
    Label(reg_window, text="Username:", font=("Arial", 12), bg="#d9f9d9").pack(pady=5)
    reg_user = StringVar()
    Entry(reg_window, textvariable=reg_user, width=35).pack(pady=5)

    Label(reg_window, text="Password:", font=("Arial", 12), bg="#d9f9d9").pack(pady=5)
    reg_pass = StringVar()
    password_entry = Entry(reg_window, textvariable=reg_pass, show="*", width=35)
    password_entry.pack(pady=5)

    def toggle_reg_password():
        if password_entry.cget('show') == '':
            password_entry.config(show='*')
            toggle_button.config(text='Show')
        else:
            password_entry.config(show='')
            toggle_button.config(text='Hide')

    toggle_button = Button(reg_window, text="Show", command=toggle_reg_password, width=6)
    toggle_button.pack(pady=2)

    Button(reg_window, text="Register", font=("Arial", 12), command=register_user,
           bg="#2196F3", fg="white", width=25, pady=10).pack(pady=20)
    reg_window.mainloop()

def login_user_window():
    global login_window, login_user_var, login_pass_var, login_password_entry, toggle_login_button
    login_window = Tk()
    login_window.title("Login")
    login_window.geometry("500x350")
    login_window.config(bg="#d9f9d9")
    login_window.resizable(False, False)

    Label(login_window, text="Login", font=("Arial", 16, "bold"), bg="#d9f9d9", fg="#006400").pack(pady=15)
    Label(login_window, text="Username:", font=("Arial", 12), bg="#d9f9d9").pack(pady=5)
    login_user_var = StringVar()
    Entry(login_window, textvariable=login_user_var, width=35).pack(pady=5)

    Label(login_window, text="Password:", font=("Arial", 12), bg="#d9f9d9").pack(pady=5)
    login_pass_var = StringVar()
    login_password_entry = Entry(login_window, textvariable=login_pass_var, show="*", width=35)
    login_password_entry.pack(pady=5)

    def toggle_login_password():
        if login_password_entry.cget('show') == '':
            login_password_entry.config(show='*')
            toggle_login_button.config(text='Show')
        else:
            login_password_entry.config(show='')
            toggle_login_button.config(text='Hide')

    toggle_login_button = Button(login_window, text="Show", command=toggle_login_password, width=6)
    toggle_login_button.pack(pady=2)

    Button(login_window, text="Login", font=("Arial", 12), command=login_user,
           bg="#4CAF50", fg="white", width=25, pady=10).pack(pady=20)
    login_window.mainloop()

#First Window (Choose Register or Login)
start_window = Tk()
start_window.title("Smart Agriculture System")
start_window.geometry("500x300")
start_window.config(bg="#d9f9d9")
start_window.resizable(False, False)

Label(start_window, text="🌾 Smart Agriculture System 🌾", font=("Arial", 16, "bold"), bg="#d9f9d9", fg="#006400").pack(pady=30)

Button(start_window, text="Register", font=("Arial", 12), command=lambda:[start_window.destroy(), register_window_func()],
       bg="#2196F3", fg="white", width=25, pady=10).pack(pady=15)

Button(start_window, text="Login", font=("Arial", 12), command=lambda:[start_window.destroy(), login_user_window()],
       bg="#4CAF50", fg="white", width=25, pady=10).pack(pady=10)

start_window.mainloop()
