import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import socket


# ------------------ Scanner Functions ------------------

def check_security_headers(url, output_box):
    output_box.insert(tk.END, "\n[+] Checking Security Headers...\n", "title")

    try:
        r = requests.get(url)
        headers = r.headers

        essential_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for h in essential_headers:
            if h not in headers:
                output_box.insert(tk.END, f"[!] Missing Header: {h}\n", "bad")
            else:
                output_box.insert(tk.END, f"[OK] {h} is present\n", "good")

    except Exception as e:
        output_box.insert(tk.END, f"[Error] Unable to fetch headers: {e}\n", "bad")


def scan_open_ports(host, output_box):
    output_box.insert(tk.END, "\n[+] Scanning Common Ports...\n", "title")

    common_ports = [80, 443, 21, 22, 25, 3306]

    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((host, port))
        if result == 0:
            output_box.insert(tk.END, f"[OPEN] Port {port} is open\n", "bad")
        else:
            output_box.insert(tk.END, f"[CLOSED] Port {port}\n", "good")

        s.close()


# ------------------ GUI Logic ------------------

def start_scan():
    url = url_entry.get().strip()

    if url == "":
        messagebox.showerror("Error", "Please enter a valid URL!")
        return

    host = url.replace("https://", "").replace("http://", "").split("/")[0]

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, "Starting Scan...\n", "title")

    check_security_headers(url, output_box)
    scan_open_ports(host, output_box)

    output_box.insert(tk.END, "\n[+] Scan Completed Successfully!\n", "title")


# ------------------ UI Design ------------------

root = tk.Tk()
root.title("Bug Bounty Vulnerability Scanner")
root.geometry("700x550")
root.resizable(False, False)
root.configure(bg="#0f172a")  # Dark navy blue


# Title Label
title_label = tk.Label(
    root,
    text="🛡 Bug Bounty Vulnerability Scanner",
    font=("Segoe UI", 18, "bold"),
    bg="#0f172a",
    fg="#38bdf8"
)
title_label.pack(pady=20)

# URL Input Frame
input_frame = tk.Frame(root, bg="#0f172a")
input_frame.pack()

url_label = tk.Label(
    input_frame,
    text="Enter Website URL:",
    font=("Segoe UI", 12),
    fg="white",
    bg="#0f172a"
)
url_label.grid(row=0, column=0, padx=10, pady=10)

url_entry = tk.Entry(
    input_frame,
    width=45,
    font=("Segoe UI", 12),
    bd=2,
    relief="solid"
)
url_entry.grid(row=0, column=1, padx=10, pady=10)

# Scan Button
scan_btn = tk.Button(
    root,
    text="Start Scan",
    font=("Segoe UI", 14, "bold"),
    bg="#38bdf8",
    fg="black",
    width=20,
    command=start_scan
)
scan_btn.pack(pady=10)

# Output Box
output_box = scrolledtext.ScrolledText(
    root,
    width=80,
    height=18,
    font=("Consolas", 11),
    bg="#1e293b",
    fg="white",
    insertbackground="white"
)
output_box.pack(pady=20)

# Text Tag Colors
output_box.tag_config("good", foreground="#4ade80")   # green
output_box.tag_config("bad", foreground="#f87171")    # red
output_box.tag_config("title", foreground="#60a5fa")  # light blue

root.mainloop()
