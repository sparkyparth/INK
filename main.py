import tkinter as tk
from tkinter import scrolledtext, messagebox
import datetime
import os
import hashlib
import random
import pandas as pd
from cryptography.fernet import Fernet
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- Configuration ---
JOURNAL_DIR = "journal_entries"
PASSWORD_FILE = "password.key"
ENCRYPTION_KEY_FILE = "encryption.key"
QUOTE_FILE = "Quote_data.csv"

class JournalApp:
    def __init__(self, master):
        self.master = master
        master.title("My Secure Journal")
        self.master.configure(bg="#1e1e1e")
        self.master.rowconfigure(2, weight=1)
        self.master.columnconfigure(0, weight=1)

        self.quotes = self.load_quotes()
        self.check_password()

    def load_quotes(self):
        if os.path.exists(QUOTE_FILE):
            df = pd.read_csv(QUOTE_FILE)
            return df[['Quote', 'Author']].dropna().values.tolist()
        return [["Stay positive, work hard, make it happen.", "Unknown"]]

    def get_random_quote(self):
        return random.choice(self.quotes)

    def check_password(self):
        if not os.path.exists(PASSWORD_FILE):
            self.create_password()
        else:
            self.ask_password()

    def create_password(self):
        password_window = tk.Toplevel(self.master)
        password_window.title("Set Password")
        password_window.configure(bg="#1e1e1e")
        password_window.transient(self.master)
        password_window.grab_set()
        password_window.focus_set()

        tk.Label(password_window, text="Enter new password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack(padx=10, pady=5)

        tk.Label(password_window, text="Confirm password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        confirm_entry = tk.Entry(password_window, show="*")
        confirm_entry.pack(padx=10, pady=5)

        def save_new_password():
            pw = password_entry.get()
            confirm_pw = confirm_entry.get()
            if pw == confirm_pw:
                hashed_pw = hashlib.sha256(pw.encode()).hexdigest()
                with open(PASSWORD_FILE, "w") as f:
                    f.write(hashed_pw)
                self.generate_encryption_key()
                password_window.destroy()
                self.setup_ui()
            else:
                messagebox.showerror("Error", "Passwords do not match.")

        tk.Button(password_window, text="Save Password", bg="#007acc", fg="#ffffff", command=save_new_password).pack(pady=10)

    def ask_password(self):
        password_window = tk.Toplevel(self.master)
        password_window.title("Enter Password")
        password_window.configure(bg="#1e1e1e")
        password_window.transient(self.master)
        password_window.grab_set()
        password_window.focus_set()

        tk.Label(password_window, text="Enter password:", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=5)
        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack(padx=10, pady=5)

        def verify_password():
            entered_pw = password_entry.get()
            hashed_entered_pw = hashlib.sha256(entered_pw.encode()).hexdigest()
            with open(PASSWORD_FILE, "r") as f:
                stored_hash = f.read().strip()
            if hashed_entered_pw == stored_hash:
                password_window.destroy()
                self.setup_ui()
            else:
                messagebox.showerror("Error", "Incorrect password.")

        tk.Button(password_window, text="Unlock", bg="#007acc", fg="#ffffff", command=verify_password).pack(pady=10)

    def generate_encryption_key(self):
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
            key_file.write(key)

    def load_encryption_key(self):
        try:
            with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
                return Fernet(key_file.read())
        except FileNotFoundError:
            messagebox.showerror("Error", "Encryption key not found!")
            return None

    def setup_ui(self):
        os.makedirs(JOURNAL_DIR, exist_ok=True)
        self.fernet = self.load_encryption_key()

        quote, author = self.get_random_quote()
        self.quote_label = tk.Label(
            self.master,
            text=f"“{quote}”\n- {author}",
            fg="#00ffcc",
            bg="#1e1e1e",
            wraplength=600,
            justify="center",
            font=("Helvetica", 12, "italic")
        )
        self.quote_label.grid(row=0, column=0, sticky="n", padx=10, pady=5)

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

    def start_saving_animation(self):
        self.saving_animation_running = True
        self.animation_texts = ["Saving.", "Saving..", "Saving..."]
        self.current_animation_index = 0
        self.update_saving_animation()

    def update_saving_animation(self):
        if self.saving_animation_running:
            text = self.animation_texts[self.current_animation_index % len(self.animation_texts)]
            self.quote_label.config(text=text)
            self.current_animation_index += 1
            self.master.after(500, self.update_saving_animation)

    def stop_saving_animation(self):
        self.saving_animation_running = False

    def save_entry(self):
        entry = self.entry_text.get("1.0", tk.END).strip()
        if entry:
            date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")
            filename = os.path.join(JOURNAL_DIR, f"{date_str}.txt")
            if self.fernet:
                encrypted_entry = self.fernet.encrypt(entry.encode())
                self.start_saving_animation()

                def do_save():
                    try:
                        with open(filename, "wb") as f:
                            f.write(encrypted_entry)
                        self.entry_text.delete("1.0", tk.END)
                        self.stop_saving_animation()
                        quote, author = self.get_random_quote()
                        self.quote_label.config(
                            text=f"“{quote}”\n- {author}"
                        )
                        messagebox.showinfo("Saved", f"Entry saved for {datetime.date.today()}")
                    except Exception as e:
                        self.stop_saving_animation()
                        messagebox.showerror("Error", f"Could not save entry: {e}")

                self.master.after(100, do_save)
            else:
                messagebox.showerror("Error", "Encryption key not loaded.")
        else:
            messagebox.showerror("Error", "Please write something in your journal.")

    def view_entries(self):
        view_window = tk.Toplevel(self.master)
        view_window.title("View Journal Entries")
        view_window.configure(bg="#1e1e1e")

        file_list = sorted([f for f in os.listdir(JOURNAL_DIR) if f.endswith(".txt")], reverse=True)
        if not file_list:
            tk.Label(view_window, text="No entries found.", fg="#ffffff", bg="#1e1e1e").pack(padx=10, pady=10)
            return

        list_box = tk.Listbox(view_window, width=70, bg="#2e2e2e", fg="#d4d4d4", font=("Courier New", 12))
        list_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        for filename in file_list:
            list_box.insert(tk.END, filename[:-4])

        def load_selected_entry():
            selected_index = list_box.curselection()
            if selected_index:
                filename = os.path.join(JOURNAL_DIR, file_list[selected_index[0]])
                try:
                    with open(filename, "rb") as f:
                        encrypted_entry = f.read()
                    if self.fernet:
                        decrypted_entry = self.fernet.decrypt(encrypted_entry).decode()
                        entry_viewer = tk.Toplevel(view_window)
                        entry_viewer.title(file_list[selected_index[0]][:-4])
                        entry_viewer.configure(bg="#1e1e1e")

                        text_viewer = scrolledtext.ScrolledText(
                            entry_viewer,
                            font=("Courier New", 12),
                            bg="#2e2e2e",
                            fg="#d4d4d4",
                            state=tk.NORMAL
                        )
                        text_viewer.insert(tk.END, decrypted_entry)
                        text_viewer.config(state=tk.DISABLED)
                        text_viewer.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
                    else:
                        messagebox.showerror("Error", "Encryption key not loaded.")
                except FileNotFoundError:
                    messagebox.showerror("Error", "File not found.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not load entry: {e}")

        tk.Button(view_window, text="Load Selected Entry", bg="#007acc", fg="#ffffff", command=load_selected_entry).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()
