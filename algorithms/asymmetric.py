import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import random
import binascii


def show_asymmetric_interface(root, algorithm, back_command, home_command, bg_color, button_color, text_color,
                              accent_color):
    """Assimetrik shifrlash interfeysi"""

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
        "rsa": {
            "name": "RSA (Rivest-Shamir-Adleman)",
            "description": "Eng mashhur assimetrik shifrlash algoritmi"
        },
        "elgamal": {
            "name": "El-Gamal Encryption",
            "description": "Diffie-Hellman asosida yaratilgan"
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
    container.pack(fill="both", padx=40, pady=(10, 5))

    # Yuqori panel - Kalitlar
    keys_frame = tk.LabelFrame(
        container,
        text="Kalitlar",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    keys_frame.pack(fill="x", pady=(0, 10))

    # O'rta panel - Input/Output
    io_frame = tk.Frame(container, bg=bg_color, height=400)
    io_frame.pack(fill="both")
    io_frame.pack_propagate(False)  # O'lchamni majburiy saqlash

    # Input frame (chap)
    input_frame = tk.LabelFrame(
        io_frame,
        text="Plaintext",
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
        text="Natija",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    output_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

    io_frame.grid_columnconfigure(0, weight=1)
    io_frame.grid_columnconfigure(1, weight=2)
    io_frame.grid_rowconfigure(0, weight=1)

    # Kalitlar sozlamalari
    keys_inner = tk.Frame(keys_frame, bg=bg_color)
    keys_inner.pack(fill="both", padx=10, pady=10)

    # Parametrlar
    if algorithm == "rsa":
        # p, q uchun
        param1_label = tk.Label(
            keys_inner,
            text="p (tub son):",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param1_label.grid(row=0, column=0, padx=(0, 5), sticky="w")

        p_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        p_entry.insert(0, "61")
        p_entry.grid(row=0, column=1, padx=(0, 15))

        param2_label = tk.Label(
            keys_inner,
            text="q (tub son):",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param2_label.grid(row=0, column=2, padx=(0, 5), sticky="w")

        q_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        q_entry.insert(0, "53")
        q_entry.grid(row=0, column=3, padx=(0, 15))

        param3_label = tk.Label(
            keys_inner,
            text="e:",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param3_label.grid(row=0, column=4, padx=(0, 5), sticky="w")

        e_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        e_entry.insert(0, "17")
        e_entry.grid(row=0, column=5)

    else:  # El-Gamal
        param1_label = tk.Label(
            keys_inner,
            text="p (tub son):",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param1_label.grid(row=0, column=0, padx=(0, 5), sticky="w")

        p_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        p_entry.insert(0, "23")
        p_entry.grid(row=0, column=1, padx=(0, 15))

        param2_label = tk.Label(
            keys_inner,
            text="g (generator):",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param2_label.grid(row=0, column=2, padx=(0, 5), sticky="w")

        g_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        g_entry.insert(0, "5")
        g_entry.grid(row=0, column=3, padx=(0, 15))

        param3_label = tk.Label(
            keys_inner,
            text="x (maxfiy):",
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color
        )
        param3_label.grid(row=0, column=4, padx=(0, 5), sticky="w")

        x_entry = tk.Entry(
            keys_inner,
            font=("Consolas", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=12
        )
        x_entry.insert(0, "6")
        x_entry.grid(row=0, column=5)

    # Kalit generatsiya button
    def generate_keys():
        if algorithm == "rsa":
            p = int(p_entry.get())
            q = int(q_entry.get())
            e = int(e_entry.get())

            n = p * q
            phi = (p - 1) * (q - 1)
            d = mod_inverse(e, phi)

            keys_display.delete("1.0", tk.END)
            keys_display.insert(tk.END, "RSA KALITLAR:\n")
            keys_display.insert(tk.END, "=" * 50 + "\n\n")
            keys_display.insert(tk.END, f"p = {p}\n")
            keys_display.insert(tk.END, f"q = {q}\n")
            keys_display.insert(tk.END, f"n = p × q = {n}\n")
            keys_display.insert(tk.END, f"φ(n) = (p-1) × (q-1) = {phi}\n")
            keys_display.insert(tk.END, f"e = {e}\n")
            keys_display.insert(tk.END, f"d = {d}\n\n")
            keys_display.insert(tk.END, f"Ochiq kalit: (e={e}, n={n})\n")
            keys_display.insert(tk.END, f"Maxfiy kalit: (d={d}, n={n})\n")

        else:  # El-Gamal
            p = int(p_entry.get())
            g = int(g_entry.get())
            x = int(x_entry.get())

            y = mod_pow(g, x, p)

            keys_display.delete("1.0", tk.END)
            keys_display.insert(tk.END, "EL-GAMAL KALITLAR:\n")
            keys_display.insert(tk.END, "=" * 50 + "\n\n")
            keys_display.insert(tk.END, f"p = {p} (tub son)\n")
            keys_display.insert(tk.END, f"g = {g} (generator)\n")
            keys_display.insert(tk.END, f"x = {x} (maxfiy kalit)\n")
            keys_display.insert(tk.END, f"y = g^x mod p = {g}^{x} mod {p} = {y}\n\n")
            keys_display.insert(tk.END, f"Ochiq kalit: (p={p}, g={g}, y={y})\n")
            keys_display.insert(tk.END, f"Maxfiy kalit: x = {x}\n")

    gen_keys_btn = tk.Button(
        keys_inner,
        text="Kalit Generatsiya",
        command=generate_keys,
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=18,
        pady=8,
        cursor="hand2"
    )
    gen_keys_btn.grid(row=0, column=6, padx=(15, 0))

    # Kalitlar ko'rsatish
    keys_display = scrolledtext.ScrolledText(
        keys_frame,
        font=("Consolas", 12),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=4
    )
    keys_display.pack(fill="x", padx=12, pady=(8, 8))

    # Input matn
    input_text = tk.Text(
        input_frame,
        font=("Consolas", 13),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=1,
        insertbackground=text_color
    )
    input_text.pack(fill="both", expand=True, padx=12, pady=(8, 12))
    input_text.insert("1.0", "Hello!")

    # Output matn
    output_text = scrolledtext.ScrolledText(
        output_frame,
        font=("Consolas", 13),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        insertbackground=text_color
    )
    output_text.pack(fill="both", expand=True, padx=12, pady=(8, 12))

    # Yordamchi funksiyalar
    def mod_pow(base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(a, m):
        if gcd(a, m) != 1:
            return None
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    # Shifrlash
    def encrypt():
        try:
            output_text.delete("1.0", tk.END)

            plaintext = input_text.get("1.0", tk.END).strip()
            if not plaintext:
                messagebox.showerror("Xato", "Plaintext kiriting!")
                return

            if algorithm == "rsa":
                p = int(p_entry.get())
                q = int(q_entry.get())
                e = int(e_entry.get())

                n = p * q

                output_text.insert(tk.END, "=" * 70 + "\n")
                output_text.insert(tk.END, "RSA SHIFRLASH\n")
                output_text.insert(tk.END, "=" * 70 + "\n\n")

                output_text.insert(tk.END, f"Ochiq kalit: (e={e}, n={n})\n\n")
                output_text.insert(tk.END, "SHIFRLASH JARAYONI:\n")
                output_text.insert(tk.END, "─" * 70 + "\n\n")

                # Har bir belgini shifrlash
                ciphertext_nums = []
                for char in plaintext:
                    m = ord(char)
                    if m >= n:
                        output_text.insert(tk.END, f"⚠️ Belgi '{char}' ({m}) n={n} dan katta!\n")
                        output_text.insert(tk.END, "   Kichikroq p va q tanlang.\n")
                        return
                    c = mod_pow(m, e, n)
                    ciphertext_nums.append(c)
                    output_text.insert(tk.END, f"'{char}' → m={m:3d} → c = {m}^{e} mod {n} = {c}\n")

                output_text.insert(tk.END, "\n" + "─" * 70 + "\n")
                output_text.insert(tk.END, f"Ciphertext (raqamlar): {ciphertext_nums}\n")
                output_text.insert(tk.END, f"Ciphertext (hex): {' '.join(f'{c:04X}' for c in ciphertext_nums)}\n")

            else:  # El-Gamal
                p = int(p_entry.get())
                g = int(g_entry.get())
                x = int(x_entry.get())

                y = mod_pow(g, x, p)

                output_text.insert(tk.END, "=" * 70 + "\n")
                output_text.insert(tk.END, "EL-GAMAL SHIFRLASH\n")
                output_text.insert(tk.END, "=" * 70 + "\n\n")

                output_text.insert(tk.END, f"Ochiq kalit: (p={p}, g={g}, y={y})\n\n")
                output_text.insert(tk.END, "SHIFRLASH JARAYONI:\n")
                output_text.insert(tk.END, "─" * 70 + "\n\n")

                # Har bir belgini shifrlash
                for char in plaintext:
                    m = ord(char)
                    if m >= p:
                        output_text.insert(tk.END, f"⚠️ Belgi '{char}' ({m}) p={p} dan katta!\n")
                        return

                    # Tasodifiy k
                    k = random.randint(2, p - 2)
                    c1 = mod_pow(g, k, p)
                    c2 = (m * mod_pow(y, k, p)) % p

                    output_text.insert(tk.END, f"'{char}' → m={m:3d}, k={k}\n")
                    output_text.insert(tk.END, f"   c1 = g^k mod p = {g}^{k} mod {p} = {c1}\n")
                    output_text.insert(tk.END, f"   c2 = m×y^k mod p = {m}×{y}^{k} mod {p} = {c2}\n")
                    output_text.insert(tk.END, f"   Ciphertext: ({c1}, {c2})\n\n")

        except Exception as e:
            messagebox.showerror("Xato", f"Shifrlashda xatolik:\n{str(e)}")

    # Deshifrlash
    def decrypt():
        try:
            output_text.delete("1.0", tk.END)

            ciphertext_input = input_text.get("1.0", tk.END).strip()
            if not ciphertext_input:
                messagebox.showerror("Xato", "Ciphertext kiriting!")
                return

            if algorithm == "rsa":
                p = int(p_entry.get())
                q = int(q_entry.get())
                e = int(e_entry.get())

                n = p * q
                phi = (p - 1) * (q - 1)
                d = mod_inverse(e, phi)

                # Ciphertext ni parse qilish (raqamlar ro'yxati)
                try:
                    # [123, 456, 789] formatda
                    ciphertext_nums = eval(ciphertext_input)
                    if not isinstance(ciphertext_nums, list):
                        raise ValueError
                except:
                    messagebox.showerror("Xato", "Ciphertext [123, 456, 789] formatda bo'lishi kerak!")
                    return

                output_text.insert(tk.END, "=" * 70 + "\n")
                output_text.insert(tk.END, "RSA DESHIFRLASH\n")
                output_text.insert(tk.END, "=" * 70 + "\n\n")

                output_text.insert(tk.END, f"Maxfiy kalit: (d={d}, n={n})\n\n")
                output_text.insert(tk.END, "DESHIFRLASH JARAYONI:\n")
                output_text.insert(tk.END, "─" * 70 + "\n\n")

                plaintext = ""
                for c in ciphertext_nums:
                    m = mod_pow(c, d, n)
                    char = chr(m)
                    plaintext += char
                    output_text.insert(tk.END, f"c={c} → m = {c}^{d} mod {n} = {m} → '{char}'\n")

                output_text.insert(tk.END, "\n" + "─" * 70 + "\n")
                output_text.insert(tk.END, f"Plaintext: {plaintext}\n")

            else:  # El-Gamal
                messagebox.showinfo("Ma'lumot",
                                    "El-Gamal deshifrlash uchun ciphertext juftliklarini kiritish kerak.\nMasalan: [(5, 10), (7, 15)]")

        except Exception as e:
            messagebox.showerror("Xato", f"Deshifrlashda xatolik:\n{str(e)}")

    # Tozalash
    def clear_all():
        output_text.delete("1.0", tk.END)

    # Buttonlar
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=(0, 15))

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