import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import hashlib
import hmac
import base64
import binascii

def show_hash_interface(root, algorithm, back_command, bg_color, button_color, text_color, accent_color):
    """Hash funksiyalari interfeysi"""

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

    # Algoritm ma'lumotlari
    algo_info = {
        "md5": {
            "name": "MD5 (Message Digest 5)",
            "hash_size": 128,
            "description": "128-bit hash, tez lekin zaif"
        },
        "sha1": {
            "name": "SHA-1 (Secure Hash Algorithm 1)",
            "hash_size": 160,
            "description": "160-bit hash, MD5 dan xavfsizroq"
        },
        "sha256": {
            "name": "SHA-256",
            "hash_size": 256,
            "description": "256-bit hash, zamonaviy standart"
        },
        "sha512": {
            "name": "SHA-512",
            "hash_size": 512,
            "description": "512-bit hash, eng xavfsiz"
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
    title.pack(pady=(30, 5))

    # Tavsif
    desc = tk.Label(
        root,
        text=info["description"],
        font=("Segoe UI", 10),
        bg=bg_color,
        fg=text_color
    )
    desc.pack(pady=(0, 10))

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

    # Input frame
    input_frame = tk.LabelFrame(
        container,
        text="Kirish",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    input_frame.pack(fill="both", expand=True, pady=(0, 10))

    # Output frame
    output_frame = tk.LabelFrame(
        container,
        text="Hash Natijasi",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    output_frame.pack(fill="both", expand=True)

    # Sozlamalar
    settings_inner = tk.Frame(settings_frame, bg=bg_color)
    settings_inner.pack(fill="x", padx=10, pady=10)

    # Output format
    format_label = tk.Label(
        settings_inner,
        text="Chiqish formati:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    format_label.grid(row=0, column=0, padx=(0, 10), sticky="w")

    format_var = tk.StringVar(value="Hex")
    format_combo = ttk.Combobox(
        settings_inner,
        textvariable=format_var,
        values=["Hex", "Base64", "Binary"],
        width=12,
        state="readonly",
        font=("Segoe UI", 9)
    )
    format_combo.grid(row=0, column=1, padx=(0, 20))

    # HMAC checkbox
    use_hmac_var = tk.BooleanVar(value=False)
    hmac_check = tk.Checkbutton(
        settings_inner,
        text="HMAC ishlatish",
        variable=use_hmac_var,
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color,
        selectcolor=button_color,
        activebackground=bg_color,
        activeforeground=text_color
    )
    hmac_check.grid(row=0, column=2, padx=(0, 20))

    # HMAC kalit
    hmac_key_label = tk.Label(
        settings_inner,
        text="HMAC kaliti:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    hmac_key_label.grid(row=0, column=3, padx=(0, 10), sticky="w")

    hmac_key_entry = tk.Entry(
        settings_inner,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        insertbackground=text_color,
        relief=tk.FLAT,
        bd=2,
        width=25
    )
    hmac_key_entry.grid(row=0, column=4, sticky="ew")
    hmac_key_entry.insert(0, "secret_key")

    settings_inner.grid_columnconfigure(4, weight=1)

    # Input matn
    input_label = tk.Label(
        input_frame,
        text="Xabar:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    input_label.pack(anchor="w", padx=10, pady=(5, 0))

    input_text = scrolledtext.ScrolledText(
        input_frame,
        font=("Consolas", 10),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=8,
        insertbackground=text_color
    )
    input_text.pack(fill="both", expand=True, padx=10, pady=(5, 10))
    input_text.insert("1.0", "Hello, World!")

    # Output matn
    output_text = scrolledtext.ScrolledText(
        output_frame,
        font=("Consolas", 10),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=8,
        insertbackground=text_color
    )
    output_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Hash hisoblash
    def calculate_hash():
        try:
            output_text.delete("1.0", tk.END)

            # Input olish
            message = input_text.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Ogohlantirish", "Xabar kiriting!")
                return

            message_bytes = message.encode('utf-8')

            # Hash funksiyani tanlash
            if algorithm == "md5":
                hash_func = hashlib.md5
            elif algorithm == "sha1":
                hash_func = hashlib.sha1
            elif algorithm == "sha256":
                hash_func = hashlib.sha256
            elif algorithm == "sha512":
                hash_func = hashlib.sha512

            # HMAC yoki oddiy hash
            if use_hmac_var.get():
                key = hmac_key_entry.get().encode('utf-8')
                hash_obj = hmac.new(key, message_bytes, hash_func)
                hash_bytes = hash_obj.digest()
                hash_type = "HMAC-" + algorithm.upper()
            else:
                hash_obj = hash_func(message_bytes)
                hash_bytes = hash_obj.digest()
                hash_type = algorithm.upper()

            # Format tanlash
            output_format = format_var.get()

            output_text.insert(tk.END, "=" * 70 + "\n")
            output_text.insert(tk.END, f"{hash_type} HASH NATIJASI\n")
            output_text.insert(tk.END, "=" * 70 + "\n\n")

            # Xabar ma'lumotlari
            output_text.insert(tk.END, "KIRISH MA'LUMOTLARI:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            output_text.insert(tk.END, f"Xabar: {message[:100]}{'...' if len(message) > 100 else ''}\n")
            output_text.insert(tk.END, f"Uzunlik: {len(message)} belgi ({len(message_bytes)} byte)\n")
            if use_hmac_var.get():
                output_text.insert(tk.END, f"HMAC kaliti: {hmac_key_entry.get()}\n")
            output_text.insert(tk.END, "\n")

            # Hash ma'lumotlari
            output_text.insert(tk.END, "HASH MA'LUMOTLARI:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            output_text.insert(tk.END, f"Algoritm: {hash_type}\n")
            output_text.insert(tk.END, f"Hash o'lchami: {info['hash_size']} bit ({info['hash_size']//8} byte)\n")
            output_text.insert(tk.END, "\n")

            # Hash natijasi
            output_text.insert(tk.END, "HASH QIYMATI:\n")
            output_text.insert(tk.END, "─" * 70 + "\n\n")

            if output_format == "Hex":
                hash_str = binascii.hexlify(hash_bytes).decode().upper()
                output_text.insert(tk.END, "Hex format:\n")
                # 16 baytdan keyin yangi qator
                for i in range(0, len(hash_str), 32):
                    output_text.insert(tk.END, f"  {hash_str[i:i+32]}\n")

            elif output_format == "Base64":
                hash_str = base64.b64encode(hash_bytes).decode()
                output_text.insert(tk.END, "Base64 format:\n")
                output_text.insert(tk.END, f"  {hash_str}\n")

            elif output_format == "Binary":
                hash_str = ' '.join(format(byte, '08b') for byte in hash_bytes)
                output_text.insert(tk.END, "Binary format:\n")
                # 8 baytdan keyin yangi qator
                binary_parts = hash_str.split()
                for i in range(0, len(binary_parts), 8):
                    output_text.insert(tk.END, f"  {' '.join(binary_parts[i:i+8])}\n")

            output_text.insert(tk.END, "\n")

            # Qo'shimcha ma'lumotlar
            output_text.insert(tk.END, "QISQA XULOSA:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            output_text.insert(tk.END, f"Hash: {binascii.hexlify(hash_bytes).decode().upper()}\n")
            output_text.insert(tk.END, "\n")

            # Xususiyatlar
            output_text.insert(tk.END, "XUSUSIYATLAR:\n")
            output_text.insert(tk.END, "─" * 70 + "\n")
            if algorithm == "md5":
                output_text.insert(tk.END, "• Tez ishlaydi\n")
                output_text.insert(tk.END, "• ⚠️ Kriptografik jihatdan zaif\n")
                output_text.insert(tk.END, "• Fayl integrity tekshirish uchun ishlatiladi\n")
            elif algorithm == "sha1":
                output_text.insert(tk.END, "• MD5 dan xavfsizroq\n")
                output_text.insert(tk.END, "• ⚠️ Collision hujumlarga moyil\n")
                output_text.insert(tk.END, "• Git kabi tizimlarda ishlatiladi\n")
            elif algorithm == "sha256":
                output_text.insert(tk.END, "• Zamonaviy standart\n")
                output_text.insert(tk.END, "• ✓ Kriptografik jihatdan xavfsiz\n")
                output_text.insert(tk.END, "• Bitcoin va boshqa blockchain'larda ishlatiladi\n")
            elif algorithm == "sha512":
                output_text.insert(tk.END, "• Eng xavfsiz\n")
                output_text.insert(tk.END, "• ✓ Katta xavfsizlik marjini\n")
                output_text.insert(tk.END, "• Maxfiy ma'lumotlar uchun tavsiya etiladi\n")

        except Exception as e:
            messagebox.showerror("Xato", f"Hash hisoblashda xatolik:\n{str(e)}")

    # Taqqoslash funksiyasi
    def compare_hash():
        try:
            # Yangi oyna
            compare_window = tk.Toplevel(root)
            compare_window.geometry("600x400")
            compare_window.configure(bg=bg_color)

            # Markazga joylashtirish
            screen_width = compare_window.winfo_screenwidth()
            screen_height = compare_window.winfo_screenheight()
            x = (screen_width - 600) // 2
            y = (screen_height - 400) // 2
            compare_window.geometry(f"600x400+{x}+{y}")



            # Hash 1
            hash1_label = tk.Label(
                compare_window,
                text="Birinchi hash:",
                font=("Segoe UI", 10),
                bg=bg_color,
                fg=text_color
            )
            hash1_label.pack(pady=(10, 5))

            hash1_entry = tk.Entry(
                compare_window,
                font=("Consolas", 10),
                bg=button_color,
                fg=text_color,
                insertbackground=text_color,
                relief=tk.FLAT,
                bd=2,
                width=60
            )
            hash1_entry.pack(pady=5, padx=20)

            # Hash 2
            hash2_label = tk.Label(
                compare_window,
                text="Ikkinchi hash:",
                font=("Segoe UI", 10),
                bg=bg_color,
                fg=text_color
            )
            hash2_label.pack(pady=(20, 5))

            hash2_entry = tk.Entry(
                compare_window,
                font=("Consolas", 10),
                bg=button_color,
                fg=text_color,
                insertbackground=text_color,
                relief=tk.FLAT,
                bd=2,
                width=60
            )
            hash2_entry.pack(pady=5, padx=20)

            # Natija label
            result_label = tk.Label(
                compare_window,
                text="",
                font=("Segoe UI", 12, "bold"),
                bg=bg_color,
                fg=text_color
            )
            result_label.pack(pady=30)

            def do_compare():
                hash1 = hash1_entry.get().strip().upper()
                hash2 = hash2_entry.get().strip().upper()

                if not hash1 or not hash2:
                    result_label.config(text="Ikkala hash ni kiriting!", fg="#f87171")
                    return

                if hash1 == hash2:
                    result_label.config(text="✓ HASH'LAR BIR XIL!", fg="#4ade80")
                else:
                    result_label.config(text="✗ HASH'LAR FARQLI!", fg="#f87171")

            compare_btn = tk.Button(
                compare_window,
                text="Taqqoslash",
                command=do_compare,
                bg=accent_color,
                fg=text_color,
                font=("Segoe UI", 11, "bold"),
                relief=tk.FLAT,
                padx=30,
                pady=10,
                cursor="hand2"
            )
            compare_btn.pack(pady=10)

        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik:\n{str(e)}")

    # Tozalash
    def clear_all():
        output_text.delete("1.0", tk.END)

    # Nusxa olish
    def copy_hash():
        try:
            hash_text = output_text.get("1.0", tk.END)
            # Oxirgi "Hash:" qatorini topish
            for line in hash_text.split('\n'):
                if line.startswith("Hash:"):
                    hash_value = line.replace("Hash:", "").strip()
                    root.clipboard_clear()
                    root.clipboard_append(hash_value)
                    messagebox.showinfo("Muvaffaqiyat", "Hash nusxalandi!")
                    return
            messagebox.showwarning("Ogohlantirish", "Hash topilmadi!")
        except Exception as e:
            messagebox.showerror("Xato", f"Nusxa olishda xatolik:\n{str(e)}")

    # Buttonlar
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=(5, 15))

    calc_btn = tk.Button(
        button_frame,
        text="Hash Hisoblash",
        command=calculate_hash,
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=25,
        pady=10,
        cursor="hand2",
        activebackground="#c93850"
    )
    calc_btn.pack(side="left", padx=5)

    compare_btn = tk.Button(
        button_frame,
        text="Taqqoslash",
        command=compare_hash,
        bg="#3b82f6",
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=25,
        pady=10,
        cursor="hand2",
        activebackground="#2563eb"
    )
    compare_btn.pack(side="left", padx=5)

    copy_btn = tk.Button(
        button_frame,
        text="Nusxa Olish",
        command=copy_hash,
        bg="#8b5cf6",
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=25,
        pady=10,
        cursor="hand2",
        activebackground="#7c3aed"
    )
    copy_btn.pack(side="left", padx=5)

    clear_btn = tk.Button(
        button_frame,
        text="Tozalash",
        command=clear_all,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=25,
        pady=10,
        cursor="hand2"
    )
    clear_btn.pack(side="left", padx=5)