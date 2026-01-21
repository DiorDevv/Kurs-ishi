import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from Crypto.Cipher import AES, Blowfish, CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

def show_symmetric_interface(root, algorithm, back_command, bg_color, button_color, text_color, accent_color):
    """Simmetrik shifrlash interfeysi"""
    
    # Orqaga button
    back_btn = tk.Button(
        root,
        text="← Orqaga",
        command=back_command,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 10),
        relief=tk.FLAT,
        padx=15,
        pady=8,
        cursor="hand2"
    )
    back_btn.place(x=20, y=20)
    
    # Algoritm nomlari va xususiyatlari
    algo_info = {
        "aes": {
            "name": "AES (Advanced Encryption Standard)",
            "block_size": 16,  # 128 bit
            "key_sizes": [16, 24, 32],  # 128, 192, 256 bit
            "default_key_size": 16
        },
        "blowfish": {
            "name": "Blowfish",
            "block_size": 8,  # 64 bit
            "key_sizes": list(range(4, 57)),  # 32-448 bit
            "default_key_size": 16
        },
        "cast": {
            "name": "CAST-128",
            "block_size": 8,  # 64 bit
            "key_sizes": list(range(5, 17)),  # 40-128 bit
            "default_key_size": 16
        }
    }
    
    info = algo_info[algorithm]
    
    # Sarlavha
    title = tk.Label(
        root,
        text=info["name"],
        font=("Segoe UI", 18, "bold"),
        bg=bg_color,
        fg=accent_color
    )
    title.pack(pady=(30, 10))
    
    # Asosiy container
    container = tk.Frame(root, bg=bg_color)
    container.pack(expand=True, fill="both", padx=40, pady=(10, 10))
    
    # Yuqori panel - Sozlamalar
    settings_frame = tk.LabelFrame(
        container,
        text="Sozlamalar",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    settings_frame.pack(fill="x", pady=(0, 10))
    
    # O'rta panel - Input/Output
    io_frame = tk.Frame(container, bg=bg_color)
    io_frame.pack(expand=True, fill="both")
    
    # Input frame (chap)
    input_frame = tk.LabelFrame(
        io_frame,
        text="Kirish",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    input_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
    
    # Output frame (o'ng)
    output_frame = tk.LabelFrame(
        io_frame,
        text="Chiqish",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    output_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
    
    io_frame.grid_columnconfigure(0, weight=1)
    io_frame.grid_columnconfigure(1, weight=1)
    io_frame.grid_rowconfigure(0, weight=1)
    
    # Sozlamalar
    settings_inner = tk.Frame(settings_frame, bg=bg_color)
    settings_inner.pack(fill="x", padx=10, pady=10)
    
    # Kalit o'lchami
    key_label = tk.Label(
        settings_inner,
        text="Kalit o'lchami (byte):",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    key_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
    
    key_size_var = tk.StringVar(value=str(info["default_key_size"]))
    key_size_combo = ttk.Combobox(
        settings_inner,
        textvariable=key_size_var,
        values=[str(x) for x in info["key_sizes"]],
        width=8,
        state="readonly",
        font=("Segoe UI", 9)
    )
    key_size_combo.grid(row=0, column=1, padx=(0, 20))
    
    # Mode tanlash
    mode_label = tk.Label(
        settings_inner,
        text="Rejim:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    mode_label.grid(row=0, column=2, padx=(0, 10), sticky="w")
    
    mode_var = tk.StringVar(value="CBC")
    mode_combo = ttk.Combobox(
        settings_inner,
        textvariable=mode_var,
        values=["ECB", "CBC", "CFB", "OFB"],
        width=8,
        state="readonly",
        font=("Segoe UI", 9)
    )
    mode_combo.grid(row=0, column=3, padx=(0, 20))
    
    # Input format
    input_format_label = tk.Label(
        settings_inner,
        text="Kirish formati:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    input_format_label.grid(row=0, column=4, padx=(0, 10), sticky="w")
    
    input_format_var = tk.StringVar(value="Text")
    input_format_combo = ttk.Combobox(
        settings_inner,
        textvariable=input_format_var,
        values=["Text", "Hex"],
        width=8,
        state="readonly",
        font=("Segoe UI", 9)
    )
    input_format_combo.grid(row=0, column=5)
    
    # Kalit va IV kiritish
    key_iv_frame = tk.Frame(settings_frame, bg=bg_color)
    key_iv_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    # Kalit
    key_entry_label = tk.Label(
        key_iv_frame,
        text="Kalit (hex):",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    key_entry_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
    
    key_entry = tk.Entry(
        key_iv_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        insertbackground=text_color,
        relief=tk.FLAT,
        bd=2
    )
    key_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
    key_entry.insert(0, "0123456789ABCDEF" * (info["default_key_size"] // 8))
    
    # Kalit generatsiya button
    def generate_key():
        key_size = int(key_size_var.get())
        random_key = get_random_bytes(key_size)
        key_entry.delete(0, tk.END)
        key_entry.insert(0, binascii.hexlify(random_key).decode().upper())
    
    gen_key_btn = tk.Button(
        key_iv_frame,
        text="Generatsiya",
        command=generate_key,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 8),
        relief=tk.FLAT,
        padx=10,
        pady=5,
        cursor="hand2"
    )
    gen_key_btn.grid(row=0, column=2)
    
    # IV (CBC, CFB, OFB uchun)
    iv_entry_label = tk.Label(
        key_iv_frame,
        text="IV (hex):",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    iv_entry_label.grid(row=1, column=0, padx=(0, 10), pady=(5, 0), sticky="w")
    
    iv_entry = tk.Entry(
        key_iv_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        insertbackground=text_color,
        relief=tk.FLAT,
        bd=2
    )
    iv_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(5, 0))
    iv_entry.insert(0, "FEDCBA9876543210" * (info["block_size"] // 8))
    
    # IV generatsiya button
    def generate_iv():
        random_iv = get_random_bytes(info["block_size"])
        iv_entry.delete(0, tk.END)
        iv_entry.insert(0, binascii.hexlify(random_iv).decode().upper())
    
    gen_iv_btn = tk.Button(
        key_iv_frame,
        text="Generatsiya",
        command=generate_iv,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 8),
        relief=tk.FLAT,
        padx=10,
        pady=5,
        cursor="hand2"
    )
    gen_iv_btn.grid(row=1, column=2, pady=(5, 0))
    
    key_iv_frame.grid_columnconfigure(1, weight=1)
    
    # Input matn
    input_text = scrolledtext.ScrolledText(
        input_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=12,
        insertbackground=text_color
    )
    input_text.pack(fill="both", expand=True, padx=10, pady=10)
    input_text.insert("1.0", "Hello, Cryptography!")
    
    # Output matn
    output_text = scrolledtext.ScrolledText(
        output_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=12,
        insertbackground=text_color
    )
    output_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Shifrlash funksiyasi
    def encrypt():
        try:
            output_text.delete("1.0", tk.END)
            
            # Parametrlarni olish
            key_size = int(key_size_var.get())
            mode = mode_var.get()
            input_format = input_format_var.get()
            
            # Kalitni olish
            key_hex = key_entry.get().strip()
            if len(key_hex) != key_size * 2:
                messagebox.showerror("Xato", f"Kalit {key_size * 2} ta hex belgi bo'lishi kerak!")
                return
            key = binascii.unhexlify(key_hex)
            
            # Plaintext ni olish
            plaintext = input_text.get("1.0", tk.END).strip()
            if input_format == "Hex":
                try:
                    plaintext = binascii.unhexlify(plaintext.replace(" ", ""))
                except:
                    messagebox.showerror("Xato", "Noto'g'ri hex format!")
                    return
            else:
                plaintext = plaintext.encode('utf-8')
            
            # Cipher yaratish
            if algorithm == "aes":
                if mode == "ECB":
                    cipher = AES.new(key, AES.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_OFB, iv)
                    
            elif algorithm == "blowfish":
                if mode == "ECB":
                    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
                    
            elif algorithm == "cast":
                if mode == "ECB":
                    cipher = CAST.new(key, CAST.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_OFB, iv)
            
            # Padding (ECB va CBC uchun)
            if mode in ["ECB", "CBC"]:
                plaintext = pad(plaintext, info["block_size"])
            
            # Shifrlash
            ciphertext = cipher.encrypt(plaintext)
            ciphertext_hex = binascii.hexlify(ciphertext).decode().upper()
            
            # Natijani ko'rsatish
            output_text.insert(tk.END, "SHIFRLANGAN MATN (HEX):\n")
            output_text.insert(tk.END, "=" * 60 + "\n\n")
            
            # Bloklar bo'lib ko'rsatish
            block_size_hex = info["block_size"] * 2
            for i in range(0, len(ciphertext_hex), block_size_hex):
                block = ciphertext_hex[i:i+block_size_hex]
                output_text.insert(tk.END, f"Blok {i//block_size_hex + 1}: {block}\n")
            
            output_text.insert(tk.END, "\n" + "─" * 60 + "\n")
            output_text.insert(tk.END, f"Jami: {ciphertext_hex}\n")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Shifrlashda xatolik:\n{str(e)}")
    
    # Deshifrlash funksiyasi
    def decrypt():
        try:
            output_text.delete("1.0", tk.END)
            
            # Parametrlarni olish
            key_size = int(key_size_var.get())
            mode = mode_var.get()
            
            # Kalitni olish
            key_hex = key_entry.get().strip()
            if len(key_hex) != key_size * 2:
                messagebox.showerror("Xato", f"Kalit {key_size * 2} ta hex belgi bo'lishi kerak!")
                return
            key = binascii.unhexlify(key_hex)
            
            # Ciphertext ni olish (hex formatda)
            ciphertext_hex = input_text.get("1.0", tk.END).strip().replace(" ", "").replace("\n", "")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
            except:
                messagebox.showerror("Xato", "Kirish hex formatda bo'lishi kerak!")
                return
            
            # Cipher yaratish
            if algorithm == "aes":
                if mode == "ECB":
                    cipher = AES.new(key, AES.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = AES.new(key, AES.MODE_OFB, iv)
                    
            elif algorithm == "blowfish":
                if mode == "ECB":
                    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
                    
            elif algorithm == "cast":
                if mode == "ECB":
                    cipher = CAST.new(key, CAST.MODE_ECB)
                elif mode == "CBC":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_CBC, iv)
                elif mode == "CFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_CFB, iv)
                elif mode == "OFB":
                    iv_hex = iv_entry.get().strip()
                    iv = binascii.unhexlify(iv_hex)
                    cipher = CAST.new(key, CAST.MODE_OFB, iv)
            
            # Deshifrlash
            plaintext = cipher.decrypt(ciphertext)
            
            # Unpadding (ECB va CBC uchun)
            if mode in ["ECB", "CBC"]:
                try:
                    plaintext = unpad(plaintext, info["block_size"])
                except:
                    pass
            
            # Natijani ko'rsatish
            output_text.insert(tk.END, "DESHIFRLANGAN MATN:\n")
            output_text.insert(tk.END, "=" * 60 + "\n\n")
            
            try:
                plaintext_str = plaintext.decode('utf-8')
                output_text.insert(tk.END, f"Text: {plaintext_str}\n\n")
            except:
                pass
            
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
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2",
        activebackground="#c93850"
    )
    encrypt_btn.pack(side="left", padx=5)
    
    decrypt_btn = tk.Button(
        button_frame,
        text="Deshifrlash",
        command=decrypt,
        bg="#4ade80",
        fg="#1a1a2e",
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2",
        activebackground="#22c55e"
    )
    decrypt_btn.pack(side="left", padx=5)
    
    clear_btn = tk.Button(
        button_frame,
        text="Tozalash",
        command=clear_all,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2"
    )
    clear_btn.pack(side="left", padx=5)