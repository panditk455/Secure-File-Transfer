
##Simple Secure File Transfer


###  Table of Contents

* What is SiFT?
* Features
* File Structure
* Getting Started
* Requirements
* Setup
* RSA Key Generation
* How to Use

  * Start the Server
  * Start the Client
  * Log In
  * Commands
* File Upload Example
* Contributors
* License

---

### 🛠️ What is SiFT?

**SiFT (Simple File Transfer)** is a secure file transfer system that allows clients to connect to a remote server and perform basic file operations. Version 1.0 adds encryption for secure communication between the client and server.

---

### Features

* **Secure Login** using RSA public-key encryption and AES for session communication.
* **File Management**: Commands to move around, create/delete directories, and upload/download files.
* **Encryption**: AES-GCM ensures messages are confidential and tamper-proof.
* **File Integrity**: File transfers are done in chunks (1024 bytes) and verified using SHA-256 hashing.
* **Modular Protocol**: Easy to expand or adapt the system.

---

### 📁 File Structure

```
SiFT/
├── specification/
│   ├── SiFT v1.0 specification.md
├── server/
│   ├── keys/
│   │   └── keypair.pem
│   ├── rsa.py
│   ├── server.py
│   ├── siftprotocols/
│   │   ├── siftcmd.py
│   │   ├── siftdnl.py
│   │   ├── siftlogin.py
│   │   ├── siftmtp.py
│   │   └── siftupl.py
│   ├── users.txt
│   └── users/
│       ├── alice/
│       ├── bob/
│       └── charlie/
├── client/
│   ├── client.py
│   ├── keys/
│   │   └── public_key.pem
│   ├── siftprotocols/
│   │   ├── siftcmd.py
│   │   ├── siftdnl.py
│   │   ├── siftlogin.py
│   │   ├── siftmtp.py
│   │   └── siftupl.py
│   ├── test_1.txt
│   └── test_2.txt
├── README.md
├── requirements.txt
└── LICENSE
```

---

### ⚙ Getting Started

---

###  Requirements

* Python 3.8+
* `pip` (Python package manager)
* OpenSSL (for generating RSA keys)

---

###  Setup

1. **Clone the repository:**

```bash
git clone https://github.com/panditk455/Secure-File-Transfer.git
cd SiFT-v1.0
```

2. **Install dependencies:**

```bash
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

###  Generate RSA Keys

Navigate to the server directory and generate a keypair:

```bash
cd server
python3 rsa.py
```

---

### ▶️How to Use

#### 1. Run the Server:

```bash
cd server
python3 server.py
```

#### 2. Run the Client:

Open a new terminal window:

```bash
cd client
python3 client.py
```

---

###  Log In

You'll be asked to log in with a test account:

* **alice / aaa**
* **bob / bbb**
* **charlie / ccc**

```plaintext
Username: alice
Password: aaa
```

---

###  Commands

Once logged in, type `help` to see the full list of available commands:

| Command      | Description                     |
| ------------ | ------------------------------- |
| `pwd`        | Show current directory          |
| `lst`        | List files and folders          |
| `chd [dir]`  | Change directory                |
| `mkd [dir]`  | Make a new directory            |
| `del [name]` | Delete a file or directory      |
| `upl [file]` | Upload a file to the server     |
| `dnl [file]` | Download a file from the server |
| `exit`       | Exit the client                 |

---

### Uploading a File – Example

**Command:**

```plaintext
upl example.txt
```

**Response:**

```plaintext
upl
<request_hash>
accept
```

---

###  Contributors

* \[Kritika Pandit]
* \[Daniel Lumbu]

---

### License

This project is licensed under the MIT License. See `LICENSE` file for details.

---
