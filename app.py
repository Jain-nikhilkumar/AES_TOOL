from flask import Flask, render_template, request, redirect
import pandas as pd
from flask import send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

app = Flask(__name__)

# Define the secret key
SECRET_KEY = ''

# Function to encrypt a value using AES
def encrypt_value(value, key):
    cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
    ct_bytes = cipher.encrypt(pad(value.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# Function to decrypt a value using AES
def decrypt_value(iv, ct, key):
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Encrypt personal information in a DataFrame
def encrypt_dataframe(df, key):
    personal_info_columns = []
    encrypted_columns = {}
    
    # Define keywords to identify personal information columns
    personal_info_keywords = ['name', 'address', 'phone', 'email', 'cast','dob','age','sex','profession']
    
    # Identify columns containing personal information
    for column in df.columns:
        if any(keyword in column.lower() for keyword in personal_info_keywords):
            personal_info_columns.append(column)
    
    # Exclude 'UnitName', 'DistrictName', 'District_Name', 'Unit_Name' columns from encryption
    excluded_columns = ['UnitName', 'DistrictName', 'District_Name', 'Unit_Name']
    personal_info_columns = [col for col in personal_info_columns if col not in excluded_columns]
    
    # Encrypt personal information in identified columns for the first 100,000 rows
    for column in personal_info_columns:
        iv_list, ct_list = [], []
        for value in df[column].iloc[:100000]:  
            if pd.notnull(value):  # Check if value is not missing
                iv, ct = encrypt_value(str(value), key)
                iv_list.append(iv)
                ct_list.append(ct)
            else:
                iv_list.append(None)  # Add None for missing values
                ct_list.append(None)
        encrypted_columns[f"{column}_IV"] = iv_list
        encrypted_columns[f"{column}_CT"] = ct_list
        df.drop(columns=[column], inplace=True)
    
    # Add encrypted columns to DataFrame
    for key, value in encrypted_columns.items():
        df[key] = value


# Decrypt personal information in a DataFrame
def decrypt_dataframe(df, key):
    for column in df.columns:
        if column.endswith('_CT'):
            iv_column = column.replace('_CT', '_IV')
            decrypted_values = []
            for i in range(len(df)):
                iv = df.at[i, iv_column]
                ct = df.at[i, column]
                if pd.notnull(iv) and pd.notnull(ct):
                    decrypted_value = decrypt_value(iv, ct, key)
                else:
                    decrypted_value = None
                decrypted_values.append(decrypted_value)
            df[column.replace('_CT', '')] = decrypted_values
            df.drop(columns=[column, iv_column], inplace=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    global SECRET_KEY

    if request.method == 'POST':
        if request.form['action'] == 'Encrypt':
            key = request.form['key']
            SECRET_KEY = bytes(key, 'utf-8')
            file = request.files['file']
            df = pd.read_csv(file, nrows=100000)  # Limit to first 100,000 rows
            encrypt_dataframe(df, SECRET_KEY)
            df.to_csv('encrypted.csv', index=False)
            return render_template('encrypted.html')
        
        elif request.form['action'] == 'Decrypt':
            key = request.form['key']
            SECRET_KEY = bytes(key, 'utf-8')
            file = request.files['file']
            df = pd.read_csv(file)
            try:
                decrypt_dataframe(df, SECRET_KEY)
                df.to_csv('decrypted.csv', index=False)
                return render_template('decrypted.html')
            except ValueError:
                return render_template('wrongkey.html') 
    return render_template('index.html')

@app.route('/')
def download_encrypted():
    encrypted_file_path = r'E:\NIKHIL\ML'  # Specify the full file path including the file name
    return send_file(encrypted_file_path, as_attachment=True)

@app.route('/download/decrypted')
def download_decrypted():
    decrypted_file_path = r'E:\NIKHIL\ML\download\decrypted.csv'  # Specify the full file path including the file name
    return send_file(decrypted_file_path, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
