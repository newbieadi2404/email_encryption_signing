import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import ttkbootstrap as tb
from ttkbootstrap.tooltip import ToolTip
from key_utils import load_private_key, load_public_key
from crypto_utils import encrypt_message, decrypt_message, sign_message, verify_signature
from email_utils import compose_email, send_email_via_smtp

# --- Status bar helper ---
def set_status(msg, style="info"):
    status_var.set(msg)
    if style == "info":
        status_bar.config(bootstyle="info")
    elif style == "success":
        status_bar.config(bootstyle="success")
    elif style == "danger":
        status_bar.config(bootstyle="danger")
    elif style == "warning":
        status_bar.config(bootstyle="warning")

def send_email_action():
    msg = send_msg_text.get("1.0", tk.END).strip()
    sender_email = sender_email_entry.get().strip()
    receiver_email = receiver_email_entry.get().strip()
    smtp_pass = smtp_pass_entry.get().strip()

    if not all([msg, sender_email, receiver_email, smtp_pass]):
        messagebox.showerror("Missing Info", "Please fill all fields.")
        set_status("Fill all fields.", "danger")
        return

    try:
        sender_private = load_private_key('sender')
        receiver_public = load_public_key('receiver')
        encrypted_msg = encrypt_message(msg, receiver_public)
        signature = sign_message(msg, sender_private)
        email = compose_email(sender_email, receiver_email, 'Encrypted and Signed Email', encrypted_msg, signature)
        SMTP_SERVER = 'smtp.gmail.com'
        SMTP_PORT = 465
        send_email_via_smtp(email, SMTP_SERVER, SMTP_PORT, sender_email, smtp_pass)
        messagebox.showinfo("Success", "Encrypted and signed email sent!")
        set_status("Email sent successfully!", "success")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Failed to send email.", "danger")

def decrypt_verify_action():
    encrypted_msg = recv_encrypted_text.get("1.0", tk.END).strip()
    signature = recv_signature_text.get("1.0", tk.END).strip()

    if not all([encrypted_msg, signature]):
        messagebox.showerror("Missing Info", "Encrypted message aur signature dono paste karein.")
        set_status("Paste both encrypted message and signature.", "danger")
        return

    try:
        receiver_private = load_private_key('receiver')
        sender_public = load_public_key('sender')
        decrypted_msg = decrypt_message(encrypted_msg, receiver_private)
        is_valid = verify_signature(decrypted_msg, signature, sender_public)
        result = f"Decrypted message:\n{decrypted_msg}\n\nSignature valid: {is_valid}"
        recv_result_text.config(state='normal')
        recv_result_text.delete("1.0", tk.END)
        recv_result_text.insert(tk.END, result)
        recv_result_text.config(state='disabled')
        # --- Alert Message ---
        if is_valid:
            messagebox.showinfo("सफलता", "Decryption सफल! Signature VALID है.")
            set_status("Decryption successful! Signature valid.", "success")
        else:
            messagebox.showwarning("चेतावनी", "Decryption हुआ, लेकिन Signature INVALID है!")
            set_status("Signature invalid!", "warning")
    except Exception as e:
        messagebox.showerror("Error", f"Kuch galat ho gaya:\n{e}")
        set_status("Error during decryption/verification.", "danger")

# --- Main App Window ---
root = tb.Window(themename="superhero")
root.title("Secure Email Encryption & Signing")
root.geometry("1000x950")  # Increased size
root.minsize(900, 800)
root.resizable(True, True)
try:
    root.iconbitmap("lock.ico")
except:
    pass

# --- Scrollable Canvas Setup ---
main_canvas = tk.Canvas(root, bg="#2C3E50", highlightthickness=0)
scrollbar = ttk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
main_canvas.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side="right", fill="y")
main_canvas.pack(side="left", fill="both", expand=True)

content_frame = ttk.Frame(main_canvas)
main_canvas.create_window((0, 0), window=content_frame, anchor="nw")

def on_configure(event):
    main_canvas.configure(scrollregion=main_canvas.bbox("all"))

content_frame.bind("<Configure>", on_configure)

# --- Header with App Name ---
header_label = ttk.Label(
    content_frame, 
    text="🔒 Secure Email Encryption & Signing", 
    font=("Helvetica", 22, "bold"),
    bootstyle="inverse-primary"
)
header_label.pack(pady=18)

# --- Sender Frame ---
sender_frame = ttk.Labelframe(content_frame, text="Send Encrypted & Signed Email", bootstyle="info", padding=20)
sender_frame.pack(fill="x", padx=30, pady=12)

ttk.Label(sender_frame, text="Sender Email (Gmail):").grid(row=0, column=0, sticky="e", pady=5, padx=5)
sender_email_entry = ttk.Entry(sender_frame, width=50)
sender_email_entry.grid(row=0, column=1, pady=5, padx=5)
ToolTip(sender_email_entry, text="Enter your Gmail address")

ttk.Label(sender_frame, text="Receiver Email:").grid(row=1, column=0, sticky="e", pady=5, padx=5)
receiver_email_entry = ttk.Entry(sender_frame, width=50)
receiver_email_entry.grid(row=1, column=1, pady=5, padx=5)
ToolTip(receiver_email_entry, text="Enter recipient's email address")

ttk.Label(sender_frame, text="Gmail App Password:").grid(row=2, column=0, sticky="e", pady=5, padx=5)
smtp_pass_entry = ttk.Entry(sender_frame, width=50, show="*")
smtp_pass_entry.grid(row=2, column=1, pady=5, padx=5)
ToolTip(smtp_pass_entry, text="Use a Gmail App Password, not your main password")

ttk.Label(sender_frame, text="Message to Send:").grid(row=3, column=0, sticky="ne", pady=5, padx=5)
send_msg_text = scrolledtext.ScrolledText(sender_frame, width=50, height=9, font=("Helvetica", 11))
send_msg_text.grid(row=3, column=1, pady=5, padx=5)
ToolTip(send_msg_text, text="Type the message you want to send securely")

send_btn = ttk.Button(sender_frame, text="Send Encrypted & Signed Email", bootstyle="success-outline", command=send_email_action)
send_btn.grid(row=4, column=1, pady=18, sticky="e", padx=5)

# --- Divider ---
ttk.Separator(content_frame, orient="horizontal").pack(fill="x", padx=30, pady=12)

# --- Receiver Frame ---
receiver_frame = ttk.Labelframe(content_frame, text="Decrypt & Verify Received Email", bootstyle="info", padding=20)
receiver_frame.pack(fill="x", padx=30, pady=12)

ttk.Label(receiver_frame, text="Paste Encrypted Message (base64):").grid(row=0, column=0, sticky="nw", pady=5, padx=5)
recv_encrypted_text = scrolledtext.ScrolledText(receiver_frame, width=50, height=9, font=("Helvetica", 11))
recv_encrypted_text.grid(row=0, column=1, pady=5, padx=5)
ToolTip(recv_encrypted_text, text="Paste the encrypted message from the email")

ttk.Label(receiver_frame, text="Paste Signature (base64):").grid(row=1, column=0, sticky="nw", pady=5, padx=5)
recv_signature_text = scrolledtext.ScrolledText(receiver_frame, width=50, height=5, font=("Helvetica", 11))
recv_signature_text.grid(row=1, column=1, pady=5, padx=5)
ToolTip(recv_signature_text, text="Paste the signature from the email")

decrypt_btn = ttk.Button(receiver_frame, text="Decrypt & Verify", bootstyle="warning-outline", command=decrypt_verify_action)
decrypt_btn.grid(row=2, column=1, pady=15, sticky="e", padx=5)

recv_result_text = scrolledtext.ScrolledText(receiver_frame, width=70, height=9, font=("Helvetica", 11), state='disabled', background="#23272b", foreground="#ECF0F1")
recv_result_text.grid(row=3, column=0, columnspan=2, pady=10, padx=5)
ToolTip(recv_result_text, text="Decrypted message and signature verification result will appear here")

# --- Add extra space at the bottom so last widgets are always visible ---
ttk.Label(content_frame, text="").pack(pady=30)

# --- Status Bar (fixed at the bottom) ---
status_var = tk.StringVar()
status_bar = tb.Label(root, textvariable=status_var, anchor="w", bootstyle="info")
status_bar.pack(fill="x", side="bottom")
set_status("Ready.", "info")

root.mainloop()




# to run this use cmd : python src/gui_email_crypto.py
