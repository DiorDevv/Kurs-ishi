import tkinter as tk
from tkinter import scrolledtext, messagebox


def show_prng_interface(root, algo_type, subtype, back_command, home_command, bg_color, button_color, text_color,
                        accent_color):
    """PRNG algoritm interfeysi - Arduino kodidan tarjima"""

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

    # Algoritm nomlari
    algo_names = {
        ("elementary", "linear"): "Chiziqli Generator",
        ("elementary", "nonlinear"): "Nochiziqli Generator",
        ("complex", "rsa"): "RSA Generator",
        ("complex", "bbs"): "BBS Generator",
        ("complex", "blum_micali"): "Blyum-Mikali Generator",
        ("shift", "a51"): "A5/1 Algoritmi"
    }

    title_text = algo_names.get((algo_type, subtype), "PRNG")

    # Sarlavha
    title = tk.Label(
        root,
        text=title_text,
        font=("Segoe UI", 24, "bold"),
        bg=bg_color,
        fg=accent_color
    )
    title.pack(pady=(70, 20))

    # Asosiy frame
    main_frame = tk.Frame(root, bg=bg_color)
    main_frame.pack(expand=True, fill="both", padx=40, pady=(10, 10))

    # Parametrlar frame (chap tomon)
    params_frame = tk.LabelFrame(
        main_frame,
        text="Parametrlar",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    params_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    # Natija frame (o'ng tomon)
    result_frame = tk.LabelFrame(
        main_frame,
        text="Natija",
        font=("Segoe UI", 14, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.GROOVE,
        bd=2
    )
    result_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_columnconfigure(1, weight=2)
    main_frame.grid_rowconfigure(0, weight=1)

    # Parametrlar ro'yxati
    entries = {}

    # Arduino kodiga asosan parametrlar
    if algo_type == "elementary" and subtype == "linear":
        # x1=(a*x0+c)modN
        params = [
            ("a =", "a", "1664525"),
            ("x₀ =", "x0", "1"),
            ("c =", "c", "1013904223"),
            ("N =", "N", "4294967296"),
            ("Sonlar soni:", "count", "10")
        ]
    elif algo_type == "elementary" and subtype == "nonlinear":
        # x1=(d*x0^2+a*x0+c)modN
        params = [
            ("d =", "d", "1229"),
            ("x₀ =", "x0", "1"),
            ("a =", "a", "1"),
            ("c =", "c", "351762"),
            ("N =", "N", "4294967296"),
            ("Sonlar soni:", "count", "10")
        ]
    elif algo_type == "complex" and subtype == "rsa":
        # x1=(x0^e)modN
        params = [
            ("p =", "p", "61"),
            ("q =", "q", "53"),
            ("e =", "e", "17"),
            ("x₀ =", "x0", "42"),
            ("Sonlar soni:", "count", "10")
        ]
    elif algo_type == "complex" and subtype == "bbs":
        # x1=(x0^e)modN (xb dan boshlaydi)
        params = [
            ("p =", "p", "11"),
            ("q =", "q", "19"),
            ("e =", "e", "2"),
            ("xb =", "xb", "3"),
            ("Sonlar soni:", "count", "10")
        ]
    elif algo_type == "complex" and subtype == "blum_micali":
        # x1=(g^x0)modp
        params = [
            ("p =", "p", "499"),
            ("g =", "g", "3"),
            ("x₀ =", "x0", "7"),
            ("Sonlar soni:", "count", "10")
        ]
    elif algo_type == "shift" and subtype == "a51":
        # A5/1 - 64 bitli kalit
        params = [
            ("64-bit kalit (hex):", "key", "0123456789ABCDEF"),
            ("Sonlar soni:", "count", "20")
        ]
    else:
        params = []

    # Inputlarni yaratish
    for i, (label_text, key, default_value) in enumerate(params):
        label = tk.Label(
            params_frame,
            text=label_text,
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=text_color,
            anchor="w"
        )
        label.grid(row=i, column=0, padx=12, pady=10, sticky="w")

        entry = tk.Entry(
            params_frame,
            font=("Segoe UI", 12),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2
        )
        entry.insert(0, default_value)
        entry.grid(row=i, column=1, padx=12, pady=10, sticky="ew")
        entries[key] = entry

    params_frame.grid_columnconfigure(1, weight=1)

    # Natija matn maydoni
    result_text = scrolledtext.ScrolledText(
        result_frame,
        font=("Consolas", 13),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        insertbackground=text_color
    )
    result_text.pack(expand=True, fill="both", padx=12, pady=12)

    # Arduino funksiyalari - to'g'ridan-to'g'ri tarjima

    def mod_pow(base, exp, mod):
        """Arduino'dagi modPow funksiyasi"""
        result = 1
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            base = (base * base) % mod
            exp //= 2
        return result

    def linear_generator():
        """x1=(a*x0+c)modN"""
        a = int(entries["a"].get())
        x = int(entries["x0"].get())
        c = int(entries["c"].get())
        N = int(entries["N"].get())
        count = int(entries["count"].get())

        result_text.insert(tk.END, "Chiziqli Generator\n")
        result_text.insert(tk.END, f"Formula: x₁ = (a × x₀ + c) mod N\n")
        result_text.insert(tk.END, f"x₁ = ({a} × {x} + {c}) mod {N}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        for i in range(count):
            x = (a * x + c) % N
            result_text.insert(tk.END, f"x{i + 1} = {x}\n")

    def nonlinear_generator():
        """x1=(d*x0^2+a*x0+c)modN"""
        d = int(entries["d"].get())
        x = int(entries["x0"].get())
        a = int(entries["a"].get())
        c = int(entries["c"].get())
        N = int(entries["N"].get())
        count = int(entries["count"].get())

        result_text.insert(tk.END, "Nochiziqli Generator\n")
        result_text.insert(tk.END, f"Formula: x₁ = (d × x₀² + a × x₀ + c) mod N\n")
        result_text.insert(tk.END, f"x₁ = ({d} × {x}² + {a} × {x} + {c}) mod {N}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        for i in range(count):
            x = (d * x * x + a * x + c) % N
            result_text.insert(tk.END, f"x{i + 1} = {x}\n")

    def rsa_generator():
        """x1=(x0^e)modN"""
        p = int(entries["p"].get())
        q = int(entries["q"].get())
        e = int(entries["e"].get())
        x = int(entries["x0"].get())
        count = int(entries["count"].get())

        N = p * q
        fi = (p - 1) * (q - 1)

        result_text.insert(tk.END, "RSA Generator\n")
        result_text.insert(tk.END, f"Formula: x₁ = (x₀^e) mod N\n")
        result_text.insert(tk.END, f"N = p × q = {p} × {q} = {N}\n")
        result_text.insert(tk.END, f"φ(N) = (p-1) × (q-1) = {fi}\n")
        result_text.insert(tk.END, f"x₁ = ({x}^{e}) mod {N}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        for i in range(count):
            x = mod_pow(x, e, N)
            result_text.insert(tk.END, f"x{i + 1} = {x}\n")

    def bbs_generator():
        """BBS: x1=(x0^e)modN, lekin xb dan boshlaydi"""
        p = int(entries["p"].get())
        q = int(entries["q"].get())
        e = int(entries["e"].get())
        xb = int(entries["xb"].get())
        count = int(entries["count"].get())

        N = p * q
        fi = (p - 1) * (q - 1)
        x0 = (xb * xb) % N

        result_text.insert(tk.END, "BBS (Blum-Blum-Shub) Generator\n")
        result_text.insert(tk.END, f"Formula: x₁ = (x₀^e) mod N\n")
        result_text.insert(tk.END, f"N = p × q = {p} × {q} = {N}\n")
        result_text.insert(tk.END, f"φ(N) = (p-1) × (q-1) = {fi}\n")
        result_text.insert(tk.END, f"xb = {xb}\n")
        result_text.insert(tk.END, f"x₀ = xb² mod N = {x0}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        x = x0
        for i in range(count):
            x = mod_pow(x, e, N)
            result_text.insert(tk.END, f"x{i + 1} = {x}\n")

    def blum_micali_generator():
        """x1=(g^x0)modp"""
        p = int(entries["p"].get())
        g = int(entries["g"].get())
        x = int(entries["x0"].get())
        count = int(entries["count"].get())

        result_text.insert(tk.END, "Blyum-Mikali Generator\n")
        result_text.insert(tk.END, f"Formula: x₁ = (g^x₀) mod p\n")
        result_text.insert(tk.END, f"x₁ = ({g}^{x}) mod {p}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        for i in range(count):
            x = mod_pow(g, x, p)
            result_text.insert(tk.END, f"x{i + 1} = {x}\n")

    def a51_generator():
        """A5/1 algoritmi - Arduino kodidan to'g'ri tarjima"""
        key_hex = entries["key"].get().upper()
        count = int(entries["count"].get())

        # Hex to bits
        if len(key_hex) != 16:
            messagebox.showerror("Xato", "Kalit 16 ta hex belgi bo'lishi kerak (64 bit)")
            return

        # Hex'dan bitlarga o'tkazish
        bits = []
        for hex_char in key_hex:
            if hex_char in '0123456789ABCDEF':
                val = int(hex_char, 16)
                for j in range(3, -1, -1):
                    bits.append((val >> j) & 1)
            else:
                messagebox.showerror("Xato", f"Noto'g'ri hex belgi: {hex_char}")
                return

        # Registrlarni to'ldirish
        X = bits[0:19]
        Y = bits[19:41]
        Z = bits[41:64]

        result_text.insert(tk.END, "A5/1 Algoritmi\n")
        result_text.insert(tk.END, f"Kalit (hex): {key_hex}\n")
        result_text.insert(tk.END, f"X registri (19 bit): {''.join(map(str, X))}\n")
        result_text.insert(tk.END, f"Y registri (22 bit): {''.join(map(str, Y))}\n")
        result_text.insert(tk.END, f"Z registri (23 bit): {''.join(map(str, Z))}\n\n")
        result_text.insert(tk.END, "Natijalar:\n")
        result_text.insert(tk.END, "─" * 50 + "\n")

        def shift_register(reg, new_bit):
            """Registrni siljitish"""
            return [new_bit] + reg[:-1]

        def is_all_zero(reg):
            """Registr nolga tengmi?"""
            return all(b == 0 for b in reg)

        # Bitlarni generatsiya qilish
        for i in range(count):
            # Output bit
            output_bit = X[18] ^ Y[21] ^ Z[22]

            # Yangi bitlar
            new_x = X[18] ^ X[17] ^ X[16] ^ X[13] ^ 1
            new_y = Y[21] ^ Y[20] ^ 1
            new_z = Z[22] ^ Z[21] ^ Z[20] ^ Z[7] ^ 1

            # Registrlarni siljitish
            X = shift_register(X, new_x)
            Y = shift_register(Y, new_y)
            Z = shift_register(Z, new_z)

            # Nol tekshiruvi
            if is_all_zero(X):
                X[10] = 1
            if is_all_zero(Y):
                Y[8] = 1
            if is_all_zero(Z):
                Z[10] = 1

            result_text.insert(tk.END, f"k{i} = {output_bit}\n")

    # Hisoblash funksiyasi
    def calculate():
        try:
            result_text.delete(1.0, tk.END)

            if algo_type == "elementary" and subtype == "linear":
                linear_generator()
            elif algo_type == "elementary" and subtype == "nonlinear":
                nonlinear_generator()
            elif algo_type == "complex" and subtype == "rsa":
                rsa_generator()
            elif algo_type == "complex" and subtype == "bbs":
                bbs_generator()
            elif algo_type == "complex" and subtype == "blum_micali":
                blum_micali_generator()
            elif algo_type == "shift" and subtype == "a51":
                a51_generator()

        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik yuz berdi:\n{str(e)}")

    # Tozalash funksiyasi
    def clear_result():
        result_text.delete(1.0, tk.END)

    # Buttonlar frame (pastda, bir qatorda)
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=15)

    # Hisoblash buttoni
    calc_btn = tk.Button(
        button_frame,
        text="Hisoblash",
        command=calculate,
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 14, "bold"),
        relief=tk.FLAT,
        padx=45,
        pady=14,
        cursor="hand2",
        activebackground="#c93850"
    )
    calc_btn.pack(side="left", padx=12)

    # Tozalash buttoni
    clear_btn = tk.Button(
        button_frame,
        text="Tozalash",
        command=clear_result,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 14, "bold"),
        relief=tk.FLAT,
        padx=45,
        pady=14,
        cursor="hand2"
    )
    clear_btn.pack(side="left", padx=12)