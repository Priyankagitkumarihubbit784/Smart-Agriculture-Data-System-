import sqlite3
import hashlib

# Connect to the database
conn = sqlite3.connect('agriculture.db')
cursor = conn.cursor()

# Hash old passwords if any
cursor.execute("SELECT id, password FROM users")
users = cursor.fetchall()

for user in users:
    user_id = user[0]
    plain_pass = user[1]

    # Check if password is already hashed (simple length check for SHA256)
    if len(plain_pass) != 64:  
        hashed_pass = hashlib.sha256(plain_pass.encode()).hexdigest()
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hashed_pass, user_id))

conn.commit()

#Clean up crops table
cursor.execute("DELETE FROM crops WHERE soil_type IS NULL OR water_need IS NULL")

# Reinsert correct crops
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

# Clear existing crops before reinserting to avoid duplicates
cursor.execute("DELETE FROM crops")
cursor.executemany('INSERT INTO crops (name, soil_type, water_need) VALUES (?, ?, ?)', crops)
conn.commit()

#View all users
cursor.execute("SELECT * FROM users")
users = cursor.fetchall()
print("Users (passwords are hashed):")
for user in users:
    print(user)

#View all crops
cursor.execute("SELECT * FROM crops")
crops = cursor.fetchall()
print("\nCrops:")
for crop in crops:
    print(crop)

conn.close()
