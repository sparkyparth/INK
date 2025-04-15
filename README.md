# INK
---

# 📝 INK 

Welcome to **My Secure Journal** — a privacy-first digital journal that encrypts your thoughts, summarizes your reflections, and keeps you inspired along the way. Whether you're recording memories, planning your future, or capturing daily gratitude, your entries are protected and personal.

---

## 💡 Features

- 🔐 **Password-Protected Access**  
  Your journal is locked behind a password hash for local authentication.

- 🗝️ **AES Encryption with Fernet**  
  All your entries are encrypted and stored securely on your machine.

- ✨ **Automatic AI Summarization**  
  Entries are summarized using an advanced Transformer model (T5) for easy file naming and quick browsing.

- 💬 **Daily Motivational Quotes**  
  Be greeted with a random motivational quote each time you log in.

- 📂 **Simple Entry Management**  
  Save, view, and browse encrypted entries through an intuitive and clean Tkinter GUI.

---

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/my-secure-journal.git
cd my-secure-journal
```

2. Install the required Python packages:

```bash
pip install transformers cryptography tkinter
```

_(On some systems, Tkinter might be pre-installed, otherwise use your package manager: `sudo apt-get install python3-tk` on Ubuntu.)_

3. Ensure you have a CSV file named `Quote_data.csv`  
Format:
```csv
Quote,Author
"The only limit to our realization of tomorrow is our doubts of today.",Franklin D. Roosevelt
...
```

---

## 🚀 Usage

Run the journal app:

```bash
python your_journal_file.py
```

### First Launch:
- You'll be asked to create a password.
- An encryption key will be generated and stored locally.

### Subsequent Launches:
- Enter your password to unlock your journal.
- Enjoy secure journaling with encryption and AI-assisted summaries.

---

## 🔒 Security Notes

- Your entries are encrypted with Fernet symmetric encryption (`cryptography` library).
- Passwords are stored as SHA-256 hashes (never plain text).
- The encryption key is stored locally; if you lose this key, encrypted entries cannot be recovered.

---

## 💡 AI-Powered Summarization

When you save an entry, a short AI-generated summary is created using OpenAI’s T5 model. This helps with:
- Smart file naming.
- Quick identification of entries.

> _Note: Summarization is local and does not require an internet connection after the first model download._

---

## 💻 Tech Stack

- Python 🐍
- Tkinter — GUI framework.
- Huggingface Transformers — AI summarization.
- Cryptography — for secure data encryption.
- CSV — for dynamic motivational quotes.

---

## 📢 Future Enhancements

- [ ] Export decrypted entries to PDF or Markdown.
- [ ] Tag-based search and filtering.
- [ ] Auto-backup and sync options.
- [ ] Dark/light mode toggle.

---

## 📜 License

MIT License — Feel free to modify and distribute, but please give credit!

---

## 🙌 Acknowledgments

- Huggingface for the T5 model.
- The Python Cryptography team for reliable encryption.
- Everyone who keeps a journal — you're writing your own history.

---

USE INK_MAIN.PY FOR ACTUAL FILE , REST ALL ARE JUST DUMMY FILES
