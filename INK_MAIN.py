# Imports for NLP, encryption, UI, and file handling
from transformers import T5Tokenizer, T5ForConditionalGeneration
import os
import hashlib
import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import random
import csv

# Initialize T5 model and tokenizer for summarizing journal entries
tokenizer = T5Tokenizer.from_pretrained('t5-base')
model = T5ForConditionalGeneration.from_pretrained('t5-base')

# Define file paths and constants
JOURNAL_DIR = "journal_entries"
PASSWORD_FILE = "password.key"
ENCRYPTION_KEY_FILE = "encryption.key"
QUOTES_CSV = "Quote_data.csv"

# Function to load motivational quotes from CSV file
def load_quotes_from_csv(file_path):
    quotes = []
    if os.path.exists(file_path):
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                quote = row.get("Quote", "").strip()
                author = row.get("Author", "").strip()
                if quote:
                    quotes.append(f"{quote} — {author}")
    return quotes

QUOTES = load_quotes_from_csv(QUOTES_CSV)

# Main Application Class
class JournalApp:
    def __init__(self, master):
        self.master = master
        master.title("My Secure Journal")
        master.configure(bg="#1e1e1e")
        self.master.rowconfigure(2, weight=1)
        self.master.columnconfigure(0, weight=1)

        self.show_random_quote()  # Display an inspiring quote at the top
        self.check_password()     # Prompt for password setup or verification

    def show_random_quote(self):
        # Display a random quote or fallback text if none are available
        quote = random.choice(QUOTES) if QUOTES else "Stay inspired, write your story!"
        self.quote_label = tk.Label(
            self.master,
            text=f"💡 {quote}",
            fg="#00ff88",
            bg="#1e1e1e",
            font=("Arial", 10, "italic"),
            wraplength=500,
            justify="center"
        )
        self.quote_label.grid(row=0, column=0, padx=10, pady=5, sticky="n")

    def check_password(self):
        # Determine whether to set or verify password
        if not os.path.exists(PASSWORD_FILE):
            self.create_password()
        else:
            self.ask_password()

    def create_password(self):
        # UI for creating and saving a new password
        pw_window = tk.Toplevel(self.master)
        pw_window.title("Set Password")
        pw_window.configure(bg="#1e1e1e")
        pw_window.transient(self.master)
        pw_window.grab_set()
        pw_window.focus_set()

        tk.Label(pw_window, text="Enter new password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        pw_entry = tk.Entry(pw_window, show="*")
        pw_entry.pack(padx=10, pady=5)

        tk.Label(pw_window, text="Confirm password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        confirm_entry = tk.Entry(pw_window, show="*")
        confirm_entry.pack(padx=10, pady=5)

        def save_new_password():
            pw = pw_entry.get()
            confirm_pw = confirm_entry.get()
            if pw == confirm_pw:
                hashed_pw = hashlib.sha256(pw.encode()).hexdigest()
                with open(PASSWORD_FILE, "w") as f:
                    f.write(hashed_pw)
                self.generate_encryption_key()
                pw_window.destroy()
                self.setup_ui()
            else:
                messagebox.showerror("Error", "Passwords do not match.")

        tk.Button(pw_window, text="Save Password", bg="#007acc", fg="#ffffff", command=save_new_password).pack(pady=10)

    def ask_password(self):
        # UI for verifying existing password
        pw_window = tk.Toplevel(self.master)
        pw_window.title("Enter Password")
        pw_window.configure(bg="#1e1e1e")
        pw_window.transient(self.master)
        pw_window.grab_set()
        pw_window.focus_set()

        tk.Label(pw_window, text="Enter password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        pw_entry = tk.Entry(pw_window, show="*")
        pw_entry.pack(padx=10, pady=5)

        def verify_password():
            entered_pw = pw_entry.get()
            hashed_pw = hashlib.sha256(entered_pw.encode()).hexdigest()
            with open(PASSWORD_FILE, "r") as f:
                stored_hash = f.read().strip()
            if hashed_pw == stored_hash:
                pw_window.destroy()
                self.setup_ui()
            else:
                messagebox.showerror("Error", "Incorrect password.")

        tk.Button(pw_window, text="Unlock", bg="#007acc", fg="#ffffff", command=verify_password).pack(pady=10)

    def generate_encryption_key(self):
        # Generate and save encryption key for Fernet encryption
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)

    def load_encryption_key(self):
        # Load encryption key for Fernet encryption
        try:
            with open(ENCRYPTION_KEY_FILE, "rb") as f:
                return Fernet(f.read())
        except FileNotFoundError:
            messagebox.showerror("Error", "Encryption key not found!")
            return None

    def setup_ui(self):
        # Setup journal entry input area and buttons
        os.makedirs(JOURNAL_DIR, exist_ok=True)
        self.fernet = self.load_encryption_key()

        self.entry_label = tk.Label(self.master, text="New Entry:", fg="#ffffff", bg="#1e1e1e")
        self.entry_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        self.entry_text = scrolledtext.ScrolledText(
            self.master,
            font=("Courier New", 12),
            bg="#2e2e2e",
            fg="#d4d4d4",
            insertbackground="#ffffff",
            wrap=tk.WORD
        )
        self.entry_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        button_frame = tk.Frame(self.master, bg="#1e1e1e")
        button_frame.grid(row=3, column=0, pady=5)

        tk.Button(button_frame, text="Save Entry", bg="#007acc", fg="#ffffff", command=self.save_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="View Entries", bg="#007acc", fg="#ffffff", command=self.view_entries).pack(side=tk.LEFT, padx=5)

    def save_entry(self):
        # Save, encrypt, and summarize a journal entry
        entry = self.entry_text.get("1.0", tk.END).strip()
        if entry:
            summary = self.summarize_text(entry)
            safe_summary = ''.join(c for c in summary if c.isalnum() or c in (' ', '_')).strip()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = os.path.join(JOURNAL_DIR, f"{timestamp} — The one with {safe_summary}.txt")

            if self.fernet:
                encrypted_entry = self.fernet.encrypt(entry.encode())
                try:
                    with open(filename, "wb") as f:
                        f.write(encrypted_entry)
                    self.entry_text.delete("1.0", tk.END)
                    messagebox.showinfo("Saved", f"Entry saved as:\n{os.path.basename(filename)}")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not save entry: {e}")
            else:
                messagebox.showerror("Error", "Encryption key not loaded.")
        else:
            messagebox.showerror("Error", "Please write something in your journal.")

    def summarize_text(self, text):
        # Use T5 model to generate a short summary from the entry
        inputs = tokenizer.encode("summarize: " + text, return_tensors="pt", max_length=512, truncation=True)
        summary_ids = model.generate(
            inputs,
            max_length=20,
            min_length=5,
            length_penalty=2.0,
            num_beams=4,
            early_stopping=True
        )
        return tokenizer.decode(summary_ids[0], skip_special_tokens=True)

    def view_entries(self):
        # List saved encrypted journal entries like a file explorer
        view_window = tk.Toplevel(self.master)
        view_window.title("View Journal Entries")
        view_window.configure(bg="#1e1e1e")

        files = sorted(os.listdir(JOURNAL_DIR))
        if not files:
            tk.Label(view_window, text="No entries found.", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=10)
            return

        tree = ttk.Treeview(view_window, columns=("Filename", "Date"), show="headings", height=10)
        tree.heading("Filename", text="Journal Title")
        tree.heading("Date", text="Saved On")
        tree.column("Filename", width=300)
        tree.column("Date", width=150)
        tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for file in files:
            if file.endswith(".txt"):
                path = os.path.join(JOURNAL_DIR, file)
                date = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M')
                tree.insert("", "end", values=(file[:-4], date))

        def load_selected_entry(event=None):
            selected = tree.selection()
            if selected:
                filename = tree.item(selected[0])["values"][0] + ".txt"
                filepath = os.path.join(JOURNAL_DIR, filename)
                try:
                    with open(filepath, "rb") as f:
                        encrypted_entry = f.read()
                    if self.fernet:
                        decrypted_entry = self.fernet.decrypt(encrypted_entry).decode()
                        viewer = tk.Toplevel(view_window)
                        viewer.title(filename[:-4])
                        viewer.configure(bg="#1e1e1e")

                        text_widget = scrolledtext.ScrolledText(
                            viewer,
                            font=("Courier New", 12),
                            bg="#2e2e2e",
                            fg="#d4d4d4",
                            state=tk.NORMAL
                        )
                        text_widget.insert(tk.END, decrypted_entry)
                        text_widget.config(state=tk.DISABLED)
                        text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
                    else:
                        messagebox.showerror("Error", "Encryption key not loaded.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not load entry: {e}")

        tree.bind("<Double-1>", load_selected_entry)

# Launch the app
if __name__ == "__main__":
    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()
