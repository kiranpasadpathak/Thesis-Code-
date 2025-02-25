import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import random
import time
import logging
import qrcode
import hashlib
import json
import datetime
import requests  # For real banking API calls
from cryptography.fernet import Fernet

# Set up logging for audit trails
logging.basicConfig(
    filename='blockchain_kyc_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -----------------------
# Enhanced Security Functions
# -----------------------
def simulate_data_encryption(kyc_data, key):
    fernet = Fernet(key)
    encrypted_data = {}
    for field, value in kyc_data.items():
        encrypted_data[field] = fernet.encrypt(value.encode()).decode()
    print("Sensitive KYC data encrypted.")
    logging.info("Sensitive KYC data encrypted.")
    return encrypted_data

def simulate_digital_signature(data, private_key="simulated_private_key"):
    signature_data = json.dumps(data, sort_keys=True) + private_key
    signature = hashlib.sha256(signature_data.encode()).hexdigest()
    return signature

# -----------------------
# Compliance and Audit Functions
# -----------------------
def simulate_compliance_check(kyc_data):
    logging.info("Simulated compliance check passed.")
    return True

# -----------------------
# Real-Time Notifications
# -----------------------
def simulate_push_notification(message):
    print("Push Notification Sent:", message)
    logging.info("Push Notification Sent: " + message)

# -----------------------
# Scalability and Integration Functions
# -----------------------
def simulate_data_interoperability(kyc_data):
    print("Data is formatted for interoperability with existing banking systems.")
    logging.info("Data is formatted for interoperability with existing banking systems.")
    return True

# -----------------------
# Blockchain Components with Digital Signature
# -----------------------
class Block:
    def __init__(self, index, timestamp, data, previous_hash, signature=""):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.signature = signature
        self.hash = self.compute_hash()
    
    def compute_hash(self):
        block_data = {
            'index': self.index,
            'timestamp': str(self.timestamp),
            'data': self.data,
            'previous_hash': self.previous_hash,
            'signature': self.signature
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = Block(0, datetime.datetime.now(), "Genesis Block", "0", signature="genesis_signature")
        self.chain.append(genesis_block)
    
    def get_last_block(self):
        return self.chain[-1]
    
    def add_block(self, data, private_key="simulated_private_key"):
        last_block = self.get_last_block()
        index = last_block.index + 1
        timestamp = datetime.datetime.now()
        previous_hash = last_block.hash
        signature = simulate_digital_signature(data, private_key)
        new_block = Block(index, timestamp, data, previous_hash, signature=signature)
        self.chain.append(new_block)
        print(f"Block {new_block.index} added with hash: {new_block.hash}")
        logging.info(f"Block {new_block.index} added with hash: {new_block.hash}")
        return new_block

# -----------------------
# Utility Functions
# -----------------------
def generate_otp():
    return ''.join(str(random.randint(0, 9)) for _ in range(6))

def generate_unique_id():
    return ''.join(str(random.randint(0, 9)) for _ in range(12))

def generate_qr_code(data, filename="blockchain_kyc_qrcode.png"):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    print(f"QR code generated and saved as {filename}")
    logging.info(f"QR code generated and saved as {filename}")
    return filename

# -----------------------
# Real Banking API Integration (with Secure Communication)
# -----------------------
def real_banking_api_call(kyc_data):
    """
    Make a secure HTTPS POST request to a real banking API.
    Replace the endpoint URL and API key/token as needed.
    For certificate pinning, provide the path to your CA bundle in the 'verify' parameter.
    """
    api_endpoint = "https://httpbin.org/post"  # Replace with real endpoint in production
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer <YOUR_API_KEY_HERE>"  # Replace with your API key/token
    }
    try:
        # For certificate pinning, replace verify=True with verify="path/to/ca_bundle.pem"
        response = requests.post(api_endpoint, json=kyc_data, headers=headers, timeout=10, verify=True)
        response.raise_for_status()  # Raise exception for HTTP errors
        print("Real Banking API call successful with status code:", response.status_code)
        logging.info("Real Banking API call successful with status code: %s", response.status_code)
        return True
    except requests.exceptions.HTTPError as http_err:
        print("HTTP error occurred during Banking API call:", http_err)
        logging.error("HTTP error during Banking API call: %s", http_err)
        return False
    except requests.exceptions.RequestException as err:
        print("Error during Banking API call:", err)
        logging.error("Error during Banking API call: %s", err)
        return False

# -----------------------
# GUI Application Class with Dashboard and MFA
# -----------------------
class KYCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Blockchain Technology for KYC Verification")
        self.geometry("800x800")
        self.configure(bg="#f2f2f2")
        self.resizable(True, True)
        self.blockchain = Blockchain()
        self.encryption_key = Fernet.generate_key()
        self.create_widgets()

    def create_widgets(self):
        header_frame = tk.Frame(self, bg="#004080", height=100)
        header_frame.pack(fill="x")

        header_title = tk.Label(header_frame,
                                text="Blockchain Technology for KYC Verification",
                                fg="white", bg="#004080",
                                font=("Helvetica", 24, "bold"))
        header_title.pack(side="left", padx=20, pady=30)

        dashboard_button = tk.Button(header_frame, text="View Dashboard", font=("Helvetica", 12, "bold"),
                                     bg="#008080", fg="white", command=self.open_dashboard)
        dashboard_button.pack(side="right", padx=20, pady=30)

        card_frame = tk.Frame(self, bg="white", bd=2, relief="groove")
        card_frame.place(relx=0.05, rely=0.15, relwidth=0.9, relheight=0.75)

        self.unique_id = generate_unique_id()
        tk.Label(card_frame, text=f"Unique ID: {self.unique_id}",
                 font=("Arial", 14, "bold"), bg="white").pack(pady=10)

        form_frame = tk.Frame(card_frame, bg="white")
        form_frame.pack(pady=10, padx=20)

        tk.Label(form_frame, text="Full Name:", bg="white", font=("Arial", 12)).grid(row=0, column=0, sticky="e", pady=8)
        self.name_entry = tk.Entry(form_frame, width=40, font=("Arial", 12))
        self.name_entry.grid(row=0, column=1, pady=8, padx=8)

        tk.Label(form_frame, text="DOB (YYYY/M/D):", bg="white", font=("Arial", 12)).grid(row=1, column=0, sticky="e", pady=8)
        self.dob_entry = tk.Entry(form_frame, width=40, font=("Arial", 12))
        self.dob_entry.grid(row=1, column=1, pady=8, padx=8)

        tk.Label(form_frame, text="Gender:", bg="white", font=("Arial", 12)).grid(row=2, column=0, sticky="e", pady=8)
        self.gender_entry = tk.Entry(form_frame, width=40, font=("Arial", 12))
        self.gender_entry.grid(row=2, column=1, pady=8, padx=8)

        tk.Label(form_frame, text="Address:", bg="white", font=("Arial", 12)).grid(row=3, column=0, sticky="e", pady=8)
        self.address_entry = tk.Entry(form_frame, width=40, font=("Arial", 12))
        self.address_entry.grid(row=3, column=1, pady=8, padx=8)

        tk.Label(form_frame, text="Mobile Number:", bg="white", font=("Arial", 12)).grid(row=4, column=0, sticky="e", pady=8)
        self.mobile_entry = tk.Entry(form_frame, width=40, font=("Arial", 12))
        self.mobile_entry.grid(row=4, column=1, pady=8, padx=8)

        self.submit_button = tk.Button(card_frame, text="Submit KYC", font=("Arial", 14, "bold"),
                                       bg="#006600", fg="white", command=self.submit_kyc)
        self.submit_button.pack(pady=20)

        self.notification_label = tk.Label(card_frame, text="", font=("Arial", 12), bg="white", fg="blue")
        self.notification_label.pack(pady=5)

    def submit_kyc(self):
        self.notification_label.config(text="")
        logging.info("KYC process initiated from GUI.")
        print("Starting KYC process...")

        name = self.name_entry.get().strip()
        dob = self.dob_entry.get().strip()
        gender = self.gender_entry.get().strip()
        address = self.address_entry.get().strip()
        mobile = self.mobile_entry.get().strip()

        expected_name = "Kiran Pathak"
        expected_dob = "2002/7/7"
        expected_gender = "Male"
        expected_address = "Naubise"
        expected_mobile = "9861160877"

        if name != expected_name:
            messagebox.showerror("Verification Failed", "Full Name is incorrect. KYC verification terminated.")
            logging.error("KYC verification failed: Incorrect Full Name.")
            self.notification_label.config(text="KYC verification failed.")
            print("KYC verification failed: Incorrect Full Name.")
            return

        if dob != expected_dob:
            messagebox.showerror("Verification Failed", "DOB is incorrect. KYC verification terminated.")
            logging.error("KYC verification failed: Incorrect DOB.")
            self.notification_label.config(text="KYC verification failed.")
            print("KYC verification failed: Incorrect DOB.")
            return

        if gender != expected_gender:
            messagebox.showerror("Verification Failed", "Gender is incorrect. KYC verification terminated.")
            logging.error("KYC verification failed: Incorrect Gender.")
            self.notification_label.config(text="KYC verification failed.")
            print("KYC verification failed: Incorrect Gender.")
            return

        if address != expected_address:
            messagebox.showerror("Verification Failed", "Address is incorrect. KYC verification terminated.")
            logging.error("KYC verification failed: Incorrect Address.")
            self.notification_label.config(text="KYC verification failed.")
            print("KYC verification failed: Incorrect Address.")
            return

        if mobile != expected_mobile:
            messagebox.showerror("Verification Failed", "Mobile Number is incorrect. KYC verification terminated.")
            logging.error("KYC verification failed: Incorrect Mobile Number.")
            self.notification_label.config(text="KYC verification failed.")
            print("KYC verification failed: Incorrect Mobile Number.")
            return

        otp = generate_otp()
        logging.info(f"Generated OTP: {otp}")
        print(f"Sending OTP {otp} to mobile number {mobile}...")
        self.update()
        self.after(1000)
        user_otp = simpledialog.askstring("OTP Verification", "Enter the OTP received:")
        if user_otp != otp:
            messagebox.showerror("Verification Failed", "Invalid OTP. KYC process terminated.")
            logging.error("OTP verification failed.")
            self.notification_label.config(text="OTP verification failed.")
            print("OTP verification failed.")
            return
        else:
            messagebox.showinfo("OTP Verified", "OTP verified successfully!")
            logging.info("OTP verified successfully.")
            self.notification_label.config(text="OTP verified successfully.")
            print("OTP verified successfully.")

        mfa_response = simpledialog.askstring("MFA Verification", "Enter your security code (numeric):")
        expected_mfa_code = "123456"
        if mfa_response != expected_mfa_code:
            messagebox.showerror("MFA Verification Failed", "Security code incorrect. KYC process terminated.")
            logging.error("MFA verification failed.")
            self.notification_label.config(text="MFA verification failed.")
            print("MFA verification failed.")
            return
        else:
            messagebox.showinfo("MFA Verified", "Security code verified successfully!")
            logging.info("MFA verified successfully.")
            print("MFA verified successfully.")

        kyc_data = {
            "unique_id": self.unique_id,
            "full_name": name,
            "dob": dob,
            "gender": gender,
            "address": address,
            "mobile": mobile
        }

        if not simulate_compliance_check(kyc_data):
            messagebox.showerror("Compliance Check Failed", "KYC data failed compliance checks.")
            logging.error("Compliance check failed.")
            self.notification_label.config(text="Compliance check failed.")
            return

        encrypted_kyc_data = simulate_data_encryption(kyc_data, self.encryption_key)
        simulate_data_interoperability(encrypted_kyc_data)

        api_success = real_banking_api_call(encrypted_kyc_data)
        if not api_success:
            messagebox.showerror("Banking API Error", "Banking API call failed. KYC process terminated.")
            logging.error("Banking API call failed. KYC process terminated.")
            self.notification_label.config(text="KYC verification failed due to API error.")
            print("Banking API call failed. KYC process terminated.")
            return

        new_block = self.blockchain.add_block(encrypted_kyc_data)
        qr_data = f"Unique ID: {self.unique_id}\nBlock Index: {new_block.index}\nBlock Hash: {new_block.hash}\nSignature: {new_block.signature}"
        qr_filename = generate_qr_code(qr_data)

        simulate_push_notification(f"KYC verified for {self.unique_id}")

        messagebox.showinfo("KYC Completed", f"KYC process completed successfully!\nQR Code saved as {qr_filename}")
        logging.info("KYC process completed successfully.")
        print("KYC process completed successfully.")
        self.notification_label.config(text="KYC process completed successfully.")

    def open_dashboard(self):
        dashboard = tk.Toplevel(self)
        dashboard.title("KYC Blockchain Dashboard")
        dashboard.geometry("600x400")
        dashboard.configure(bg="white")

        tree = ttk.Treeview(dashboard, columns=("Index", "Timestamp", "Hash", "Signature"), show='headings')
        tree.heading("Index", text="Index")
        tree.heading("Timestamp", text="Timestamp")
        tree.heading("Hash", text="Hash")
        tree.heading("Signature", text="Signature")
        tree.column("Index", width=50)
        tree.column("Timestamp", width=150)
        tree.column("Hash", width=200)
        tree.column("Signature", width=150)
        tree.pack(fill="both", expand=True)

        for block in self.blockchain.chain:
            tree.insert("", "end", values=(block.index, str(block.timestamp), block.hash, block.signature))

# -----------------------
# Main Execution
# -----------------------
if __name__ == "__main__":
    app = KYCApp()
    app.mainloop()