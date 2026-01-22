import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import binascii


def show_stream_interface(root, algorithm, back_command, home_command, bg_color, button_color, text_color,
                          accent_color):
    """Oqimli shifrlash interfeysi"""

    # Navigation frame
    nav_frame = tk.Frame(root, bg=bg_color)
    nav_frame.place(x=20, y=20)

    # Orqaga button
    back_btn = tk.Button(
        nav_frame,
        text="← Orqaga",
        command=back_command,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 12, "bold"),
        relief=tk.FLAT,
        padx=18,
        pady=10,
        cursor="hand2",
        activebackground="#103a7a",
        activeforeground=text_color
    )
    back_btn.pack(side="left", padx=(0, 10))
    back_btn.bind("<Enter>", lambda e: back_btn.config(bg="#103a7a"))
    back_btn.bind("<Leave>", lambda e: back_btn.config(bg=button_color))

    # Bosh sahifa button
    home_btn = tk.Button(
        nav_frame,
        text="🏠 Bosh sahifa",
        command=home_command,
        bg="#10b981",
        fg=text_color,
        font=("Segoe UI", 12, "bold"),
        relief=tk.FLAT,
        padx=18,
        pady=10,
        cursor="hand2",
        activebackground="#059669",
        activeforeground=text_color
    )
    home_btn.pack(side="left")
    home_btn.bind("<Enter>", lambda e: home_btn.config(bg="#059669"))
    home_btn.bind("<Leave>", lambda e: home_btn.config(bg="#10b981"))

    # Algoritm ma'lumotlari
    algo_info = {
        "rc4": {
            "name": "RC4 (Rivest Cipher 4)",
            "description": "Wi-Fi WEP da ishlatilgan, tez lekin zaif",
            "key_size": "40-2048 bit"
        },
        "a51": {
            "name": "A5/1 Stream Cipher",
            "description": "GSM telefonlarida ishlatilgan",
            "key_size": "64 bit"
        }
    }

    info = algo_info[algorithm]

    # Sarlavha
    title = tk.Label(
        root,
        text=info["name"],
        font=("Segoe UI", 24, "bold"),
        bg=bg_color,
        fg=accent_color
    )
    title.pack(pady=(70, 8))

    # Tavsif
    desc = tk.Label(
        root,
        text=info["description"],
        font=("Segoe UI", 13),
        bg=bg_color,
        fg=text_color
    )
    desc.pack(pady=(0, 15))

    # Asosiy container
    container = tk.Frame(root, bg=bg_color)
    container.pack(expand=True, fill="both", padx=40, pady=(10, 10))

    # Yuqori panel - Sozlamalar
    settings_frame = tk.LabelFrame(
        container,
        text="Sozlamalar",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    settings_frame.pack(fill="x", pady=(0, 10))

    # O'rta panel - Input/Output
    io_frame = tk.Frame(container, bg=bg_color)
    io_frame.pack(expand=True, fill="both")

    # Input frame (chap)
    input_frame = tk.LabelFrame(
        io_frame,
        text="Kirish Matni",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    input_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

    # Output frame (o'ng)
    output_frame = tk.LabelFrame(
        io_frame,
        text="Chiqish Matni",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    output_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

    io_frame.grid_columnconfigure(0, weight=1)
    io_frame.grid_columnconfigure(1, weight=1)
    io_frame.grid_rowconfigure(0, weight=1)

    # Sozlamalar
    settings_inner = tk.Frame(settings_frame, bg=bg_color)
    settings_inner.pack(fill="x", padx=10, pady=10)

    # Kalit kiritish
    key_label = tk.Label(
        settings_inner,
        text="Kalit (hex):" if algorithm == "rc4" else "Kalit (64-bit hex):",
        font=("Segoe UI", 12, "bold"),
        bg=bg_color,
        fg=text_color
    )
    key_label.grid(row=0, column=0, padx=(0, 10), sticky="w")

    key_entry = tk.Entry(
        settings_inner,
        font=("Consolas", 12),
        bg=button_color,
        fg=text_color,
        insertbackground=text_color,
        relief=tk.FLAT,
        bd=2,
        width=40
    )
    key_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

    if algorithm == "rc4":
        key_entry.insert(0, "0123456789ABCDEF")
    else:  # A5/1
        key_entry.insert(0, "0123456789ABCDEF")  # 64 bit

    # Input/Output format
    format_label = tk.Label(
        settings_inner,
        text="Format:",
        font=("Segoe UI", 12, "bold"),
        bg=bg_color,
        fg=text_color
    )
    format_label.grid(row=0, column=2, padx=(0, 10), sticky="w")

    format_var = tk.StringVar(value="Text")
    format_combo = ttk.Combobox(
        settings_inner,
        textvariable=format_var,
        values=["Text", "Hex"],
        width=10,
        state="readonly",
        font=("Segoe UI", 11)
    )
    format_combo.grid(row=0, column=3)

    settings_inner.grid_columnconfigure(1, weight=1)

    # Input matn
    input_text = scrolledtext.ScrolledText(
        input_frame,
        font=("Consolas", 13),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=12,
        insertbackground=text_color
    )
    input_text.pack(fill="both", expand=True, padx=12, pady=12)
    input_text.insert("1.0", "Hello, Stream Cipher!")

    # Output matn
    output_text = scrolledtext.ScrolledText(
        output_frame,
        font=("Consolas", 13),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=12,
        insertbackground=text_color
    )
    output_text.pack(fill="both", expand=True, padx=12, pady=12)

    # RC4 algoritmi
    class RC4:
        def __init__(self, key):
            self.key = key
            self.S = list(range(256))
            self._KSA()

        def _KSA(self):
            """Key Scheduling Algorithm"""
            j = 0
            key_length = len(self.key)
            for i in range(256):
                j = (j + self.S[i] + self.key[i % key_length]) % 256
                self.S[i], self.S[j] = self.S[j], self.S[i]

        def _PRGA(self, length):
            """Pseudo-Random Generation Algorithm"""
            i = 0
            j = 0
            keystream = []
            for _ in range(length):
                i = (i + 1) % 256
                j = (j + self.S[i]) % 256
                self.S[i], self.S[j] = self.S[j], self.S[i]
                K = self.S[(self.S[i] + self.S[j]) % 256]
                keystream.append(K)
            return keystream

        def encrypt(self, plaintext):
            keystream = self._PRGA(len(plaintext))
            ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
            return ciphertext, keystream

        def decrypt(self, ciphertext):
            # RC4 da encrypt va decrypt bir xil
            return self.encrypt(ciphertext)

    # A5/1 algoritmi
    class A51:
        def __init__(self, key_hex):
            # Hex'dan bitlarga o'tkazish
            key_bytes = binascii.unhexlify(key_hex)
            bits = []
            for byte in key_bytes:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)

            # Registrlarni to'ldirish
            self.X = bits[0:19]
            self.Y = bits[19:41]
            self.Z = bits[41:64]

        def _shift_register(self, reg, new_bit):
            """Registrni siljitish"""
            return [new_bit] + reg[:-1]

        def _is_all_zero(self, reg):
            """Registr nolga tengmi?"""
            return all(b == 0 for b in reg)

        def _clock(self):
            """Bitta bit generatsiya qilish"""
            # Output bit
            output_bit = self.X[18] ^ self.Y[21] ^ self.Z[22]

            # Yangi bitlar
            new_x = self.X[18] ^ self.X[17] ^ self.X[16] ^ self.X[13] ^ 1
            new_y = self.Y[21] ^ self.Y[20] ^ 1
            new_z = self.Z[22] ^ self.Z[21] ^ self.Z[20] ^ self.Z[7] ^ 1

            # Registrlarni siljitish
            self.X = self._shift_register(self.X, new_x)
            self.Y = self._shift_register(self.Y, new_y)
            self.Z = self._shift_register(self.Z, new_z)

            # Nol tekshiruvi
            if self._is_all_zero(self.X):
                self.X[10] = 1
            if self._is_all_zero(self.Y):
                self.Y[8] = 1
            if self._is_all_zero(self.Z):
                self.Z[10] = 1

            return output_bit

        def generate_keystream(self, length):
            """Keystream generatsiya qilish"""
            keystream_bits = []
            for _ in range(length * 8):  # har byte uchun 8 bit
                keystream_bits.append(self._clock())

            # Bitlarni byte'larga o'tkazish
            keystream = []
            for i in range(0, len(keystream_bits), 8):
                byte_bits = keystream_bits[i:i + 8]
                byte_val = 0
                for bit in byte_bits:
                    byte_val = (byte_val << 1) | bit
                keystream.append(byte_val)

            return keystream

        def encrypt(self, plaintext):
            keystream = self.generate_keystream(len(plaintext))
            ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
            return ciphertext, keystream

        def decrypt(self, ciphertext):
            # Oqimli shifrlashda encrypt va decrypt bir xil
            return self.encrypt(ciphertext)

    # Shifrlash funksiyasi
    def encrypt():
        try:
            output_text.delete("1.0", tk.END)

            # Kalitni olish
            key_hex = key_entry.get().strip()
            if not key_hex:
                messagebox.showerror("Xato", "Kalitni kiriting!")
                return

            # Plaintext ni olish
            plaintext = input_text.get("1.0", tk.END).strip()
            if not plaintext:
                messagebox.showerror("Xato", "Matnni kiriting!")
                return

            input_format = format_var.get()
            if input_format == "Hex":
                try:
                    plaintext_bytes = binascii.unhexlify(plaintext.replace(" ", ""))
                except:
                    messagebox.showerror("Xato", "Noto'g'ri hex format!")
                    return
            else:
                plaintext_bytes = plaintext.encode('utf-8')

            # Shifrlash
            if algorithm == "rc4":
                key_bytes = binascii.unhexlify(key_hex)
                cipher = RC4(key_bytes)
                ciphertext, keystream = cipher.encrypt(plaintext_bytes)
            else:  # A5/1
                if len(key_hex) != 16:
                    messagebox.showerror("Xato", "A5/1 uchun 64-bit (16 hex) kalit kerak!")
                    return
                cipher = A51(key_hex)
                ciphertext, keystream = cipher.encrypt(plaintext_bytes)

            # Natijani ko'rsatish
            output_text.insert(tk.END, "=" * 70 + "\n")
            output_text.insert(tk.END, f"{info['name'].upper()} - SHIFRLASH\n")
            output_text.insert(tk.END, "=" * 70 + "\n\n")

            output_text.insert(tk.END, "KIRISH:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            if input_format == "Text":
                output_text.insert(tk.END, f"Plaintext: {plaintext}\n")
            output_text.insert(tk.END, f"Hex: {binascii.hexlify(plaintext_bytes).decode().upper()}\n")
            output_text.insert(tk.END, f"Uzunlik: {len(plaintext_bytes)} byte\n\n")

            output_text.insert(tk.END, "KALIT:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            output_text.insert(tk.END, f"Hex: {key_hex.upper()}\n\n")

            output_text.insert(tk.END, "KEYSTREAM (birinchi 16 byte):\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            keystream_hex = ''.join(f'{k:02X}' for k in keystream[:16])
            for i in range(0, len(keystream_hex), 32):
                output_text.insert(tk.END, f"{keystream_hex[i:i + 32]}\n")
            if len(keystream) > 16:
                output_text.insert(tk.END, "...\n")
            output_text.insert(tk.END, "\n")

            output_text.insert(tk.END, "CIPHERTEXT:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            ciphertext_hex = binascii.hexlify(ciphertext).decode().upper()
            for i in range(0, len(ciphertext_hex), 32):
                output_text.insert(tk.END, f"{ciphertext_hex[i:i + 32]}\n")
            output_text.insert(tk.END, "\n")

            output_text.insert(tk.END, "XOR JARAYONI (birinchi 8 byte):\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            for i in range(min(8, len(plaintext_bytes))):
                p = plaintext_bytes[i]
                k = keystream[i]
                c = ciphertext[i]
                output_text.insert(tk.END, f"P[{i}]={p:02X} ⊕ K[{i}]={k:02X} = C[{i}]={c:02X}\n")

        except Exception as e:
            messagebox.showerror("Xato", f"Shifrlashda xatolik:\n{str(e)}")

    # Deshifrlash funksiyasi
    def decrypt():
        try:
            output_text.delete("1.0", tk.END)

            # Kalitni olish
            key_hex = key_entry.get().strip()
            if not key_hex:
                messagebox.showerror("Xato", "Kalitni kiriting!")
                return

            # Ciphertext ni olish (hex formatda)
            ciphertext_hex = input_text.get("1.0", tk.END).strip().replace(" ", "").replace("\n", "")
            if not ciphertext_hex:
                messagebox.showerror("Xato", "Ciphertext ni kiriting!")
                return

            try:
                ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
            except:
                messagebox.showerror("Xato", "Ciphertext hex formatda bo'lishi kerak!")
                return

            # Deshifrlash
            if algorithm == "rc4":
                key_bytes = binascii.unhexlify(key_hex)
                cipher = RC4(key_bytes)
                plaintext, keystream = cipher.decrypt(ciphertext_bytes)
            else:  # A5/1
                if len(key_hex) != 16:
                    messagebox.showerror("Xato", "A5/1 uchun 64-bit (16 hex) kalit kerak!")
                    return
                cipher = A51(key_hex)
                plaintext, keystream = cipher.decrypt(ciphertext_bytes)

            # Natijani ko'rsatish
            output_text.insert(tk.END, "=" * 70 + "\n")
            output_text.insert(tk.END, f"{info['name'].upper()} - DESHIFRLASH\n")
            output_text.insert(tk.END, "=" * 70 + "\n\n")

            output_text.insert(tk.END, "CIPHERTEXT:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            output_text.insert(tk.END, f"Hex: {ciphertext_hex.upper()}\n")
            output_text.insert(tk.END, f"Uzunlik: {len(ciphertext_bytes)} byte\n\n")

            output_text.insert(tk.END, "PLAINTEXT:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            try:
                plaintext_str = plaintext.decode('utf-8')
                output_text.insert(tk.END, f"Text: {plaintext_str}\n")
            except:
                output_text.insert(tk.END, "Text: (UTF-8 emas)\n")
            output_text.insert(tk.END, f"Hex: {binascii.hexlify(plaintext).decode().upper()}\n")

        except Exception as e:
            messagebox.showerror("Xato", f"Deshifrlashda xatolik:\n{str(e)}")

    # Tozalash
    def clear_all():
        output_text.delete("1.0", tk.END)

    # Buttonlar
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=(5, 15))

    encrypt_btn = tk.Button(
        button_frame,
        text="Shifrlash",
        command=encrypt,
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 14, "bold"),
        relief=tk.FLAT,
        padx=35,
        pady=12,
        cursor="hand2",
        activebackground="#c93850"
    )
    encrypt_btn.pack(side="left", padx=8)

    decrypt_btn = tk.Button(
        button_frame,
        text="Deshifrlash",
        command=decrypt,
        bg="#4ade80",
        fg="#1a1a2e",
        font=("Segoe UI", 14, "bold"),
        relief=tk.FLAT,
        padx=35,
        pady=12,
        cursor="hand2",
        activebackground="#22c55e"
    )
    decrypt_btn.pack(side="left", padx=8)

    clear_btn = tk.Button(
        button_frame,
        text="Tozalash",
        command=clear_all,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 14, "bold"),
        relief=tk.FLAT,
        padx=35,
        pady=12,
        cursor="hand2"
    )
    clear_btn.pack(side="left", padx=8)