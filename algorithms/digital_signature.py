import tkinter as tk
from tkinter import scrolledtext, messagebox
import hashlib
import random

def show_signature_interface(root, algorithm, back_command, bg_color, button_color, text_color, accent_color):
    """Elektron Raqamli Imzo interfeysi"""
    
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
    
    # Algoritm nomlari
    algo_names = {
        "dsa": "DSA (Digital Signature Algorithm)",
        "elgamal": "El-Gamal Signature",
        "rsa": "RSA Signature"
    }
    
    title_text = algo_names.get(algorithm, "ERI")
    
    # Sarlavha
    title = tk.Label(
        root,
        text=title_text,
        font=("Segoe UI", 18, "bold"),
        bg=bg_color,
        fg=accent_color
    )
    title.pack(pady=(30, 10))
    
    # Asosiy container
    container = tk.Frame(root, bg=bg_color)
    container.pack(expand=True, fill="both", padx=40, pady=(10, 10))
    
    # Chap panel - Parametrlar va xabar
    left_panel = tk.Frame(container, bg=bg_color)
    left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
    
    # O'ng panel - Natija
    right_panel = tk.Frame(container, bg=bg_color)
    right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
    
    container.grid_columnconfigure(0, weight=1)
    container.grid_columnconfigure(1, weight=2)
    container.grid_rowconfigure(0, weight=1)
    
    # Parametrlar frame
    params_frame = tk.LabelFrame(
        left_panel,
        text="Parametrlar",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    params_frame.pack(fill="x", pady=(0, 10))
    
    # Xabar frame
    message_frame = tk.LabelFrame(
        left_panel,
        text="Xabar",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    message_frame.pack(fill="both", expand=True)
    
    # Natija frame
    result_frame = tk.LabelFrame(
        right_panel,
        text="Natija",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    result_frame.pack(fill="both", expand=True)
    
    # Parametrlar inputlari
    entries = {}
    
    if algorithm == "rsa":
        params = [
            ("p (tub son):", "p", "61"),
            ("q (tub son):", "q", "53"),
            ("e (ochiq ko'rsatgich):", "e", "17")
        ]
    elif algorithm == "dsa":
        params = [
            ("p (tub son):", "p", "23"),
            ("q (p-1 bo'luvchisi):", "q", "11"),
            ("g (generator):", "g", "2"),
            ("x (maxfiy kalit, x<q):", "x", "6")
        ]
    elif algorithm == "elgamal":
        params = [
            ("p (tub son):", "p", "23"),
            ("g (primitiv ildiz):", "g", "5"),
            ("x (maxfiy kalit, x<p):", "x", "6")
        ]
    
    for i, (label_text, key, default_value) in enumerate(params):
        label = tk.Label(
            params_frame,
            text=label_text,
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color,
            anchor="w"
        )
        label.grid(row=i, column=0, padx=10, pady=5, sticky="w")
        
        entry = tk.Entry(
            params_frame,
            font=("Segoe UI", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=15
        )
        entry.insert(0, default_value)
        entry.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
        entries[key] = entry
    
    params_frame.grid_columnconfigure(1, weight=1)
    
    # Xabar kiritish
    message_label = tk.Label(
        message_frame,
        text="Imzolash uchun xabar:",
        font=("Segoe UI", 9),
        bg=bg_color,
        fg=text_color
    )
    message_label.pack(pady=(5, 0), padx=10, anchor="w")
    
    message_text = tk.Text(
        message_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        height=5,
        insertbackground=text_color
    )
    message_text.pack(fill="both", expand=True, padx=10, pady=(5, 10))
    message_text.insert("1.0", "Hello, World!")
    
    # Natija maydoni
    result_text = scrolledtext.ScrolledText(
        result_frame,
        font=("Consolas", 9),
        bg=button_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2,
        wrap=tk.WORD,
        insertbackground=text_color
    )
    result_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Yordamchi funksiyalar
    def mod_pow(base, exp, mod):
        """Modulli darajaga ko'tarish"""
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result
    
    def gcd(a, b):
        """EKUB"""
        while b:
            a, b = b, a % b
        return a
    
    def mod_inverse(a, m):
        """Modulli teskari"""
        if gcd(a, m) != 1:
            return None
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1
    
    def hash_message(msg):
        """SHA-256 hash"""
        return int(hashlib.sha256(msg.encode()).hexdigest(), 16)
    
    # RSA algoritmi
    def rsa_signature():
        try:
            result_text.delete("1.0", tk.END)
            
            p = int(entries["p"].get())
            q = int(entries["q"].get())
            e = int(entries["e"].get())
            message = message_text.get("1.0", tk.END).strip()
            
            # Kalitlarni hisoblash
            n = p * q
            phi = (p - 1) * (q - 1)
            
            # d ni hisoblash (maxfiy ko'rsatgich)
            d = mod_inverse(e, phi)
            if d is None:
                messagebox.showerror("Xato", "e va φ(n) o'zaro tub emas!")
                return
            
            result_text.insert(tk.END, "=" * 58 + "\n")
            result_text.insert(tk.END, "RSA ELEKTRON RAQAMLI IMZO\n")
            result_text.insert(tk.END, "=" * 58 + "\n\n")
            
            # Kalitlar
            result_text.insert(tk.END, "1. KALIT GENERATSIYASI:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   p = {p}\n")
            result_text.insert(tk.END, f"   q = {q}\n")
            result_text.insert(tk.END, f"   n = p × q = {n}\n")
            result_text.insert(tk.END, f"   φ(n) = (p-1) × (q-1) = {phi}\n")
            result_text.insert(tk.END, f"   e (ochiq) = {e}\n")
            result_text.insert(tk.END, f"   d (maxfiy) = {d}\n")
            result_text.insert(tk.END, f"\n   Ochiq kalit: (e={e}, n={n})\n")
            result_text.insert(tk.END, f"   Maxfiy kalit: (d={d}, n={n})\n\n")
            
            # Hash
            h = hash_message(message)
            h_mod = h % n
            result_text.insert(tk.END, "2. XABAR VA HASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Xabar: \"{message}\"\n")
            result_text.insert(tk.END, f"   Hash (SHA-256): {hex(h)[:50]}...\n")
            result_text.insert(tk.END, f"   Hash mod n: {h_mod}\n\n")
            
            # Imzolash
            signature = mod_pow(h_mod, d, n)
            result_text.insert(tk.END, "3. IMZOLASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   S = H^d mod n\n")
            result_text.insert(tk.END, f"   S = {h_mod}^{d} mod {n}\n")
            result_text.insert(tk.END, f"   Imzo (S): {signature}\n\n")
            
            # Tekshirish
            verified = mod_pow(signature, e, n)
            result_text.insert(tk.END, "4. IMZONI TEKSHIRISH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   H' = S^e mod n\n")
            result_text.insert(tk.END, f"   H' = {signature}^{e} mod {n}\n")
            result_text.insert(tk.END, f"   Hisoblangan: {verified}\n")
            result_text.insert(tk.END, f"   Kutilgan: {h_mod}\n")
            result_text.insert(tk.END, f"\n   Natija: ")
            
            if verified == h_mod:
                result_text.insert(tk.END, "✓ IMZO TO'G'RI!\n", "success")
                result_text.tag_config("success", foreground="#4ade80")
            else:
                result_text.insert(tk.END, "✗ IMZO NOTO'G'RI!\n", "error")
                result_text.tag_config("error", foreground="#f87171")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik: {str(e)}")
    
    # DSA algoritmi
    def dsa_signature():
        try:
            result_text.delete("1.0", tk.END)
            
            p = int(entries["p"].get())
            q = int(entries["q"].get())
            g = int(entries["g"].get())
            x = int(entries["x"].get())
            message = message_text.get("1.0", tk.END).strip()
            
            # Ochiq kalit
            y = mod_pow(g, x, p)
            
            result_text.insert(tk.END, "=" * 58 + "\n")
            result_text.insert(tk.END, "DSA ELEKTRON RAQAMLI IMZO\n")
            result_text.insert(tk.END, "=" * 58 + "\n\n")
            
            # Kalitlar
            result_text.insert(tk.END, "1. KALIT GENERATSIYASI:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   p = {p} (tub son)\n")
            result_text.insert(tk.END, f"   q = {q} (p-1 ning bo'luvchisi)\n")
            result_text.insert(tk.END, f"   g = {g} (generator)\n")
            result_text.insert(tk.END, f"   x = {x} (maxfiy kalit, 0 < x < q)\n")
            result_text.insert(tk.END, f"   y = g^x mod p = {g}^{x} mod {p} = {y}\n")
            result_text.insert(tk.END, f"\n   Ochiq kalit: (p, q, g, y)\n")
            result_text.insert(tk.END, f"   Maxfiy kalit: x = {x}\n\n")
            
            # Hash
            h = hash_message(message)
            h_mod = h % q
            result_text.insert(tk.END, "2. XABAR VA HASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Xabar: \"{message}\"\n")
            result_text.insert(tk.END, f"   Hash mod q: {h_mod}\n\n")
            
            # Tasodifiy k
            k = random.randint(1, q - 1)
            k_inv = mod_inverse(k, q)
            
            # Imzolash
            r = mod_pow(g, k, p) % q
            s = (k_inv * (h_mod + x * r)) % q
            
            result_text.insert(tk.END, "3. IMZOLASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Tasodifiy k = {k}\n")
            result_text.insert(tk.END, f"   r = (g^k mod p) mod q = {r}\n")
            result_text.insert(tk.END, f"   s = k⁻¹(H + xr) mod q = {s}\n")
            result_text.insert(tk.END, f"\n   Imzo: (r={r}, s={s})\n\n")
            
            # Tekshirish
            if s == 0:
                result_text.insert(tk.END, "   Xato: s = 0, qayta hisoblash kerak\n")
                return
            
            w = mod_inverse(s, q)
            u1 = (h_mod * w) % q
            u2 = (r * w) % q
            v = ((mod_pow(g, u1, p) * mod_pow(y, u2, p)) % p) % q
            
            result_text.insert(tk.END, "4. IMZONI TEKSHIRISH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   w = s⁻¹ mod q = {w}\n")
            result_text.insert(tk.END, f"   u₁ = Hw mod q = {u1}\n")
            result_text.insert(tk.END, f"   u₂ = rw mod q = {u2}\n")
            result_text.insert(tk.END, f"   v = (g^u₁ × y^u₂ mod p) mod q = {v}\n")
            result_text.insert(tk.END, f"   r = {r}\n")
            result_text.insert(tk.END, f"\n   Natija: ")
            
            if v == r:
                result_text.insert(tk.END, "✓ IMZO TO'G'RI!\n", "success")
                result_text.tag_config("success", foreground="#4ade80")
            else:
                result_text.insert(tk.END, "✗ IMZO NOTO'G'RI!\n", "error")
                result_text.tag_config("error", foreground="#f87171")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik: {str(e)}")
    
    # El-Gamal algoritmi
    def elgamal_signature():
        try:
            result_text.delete("1.0", tk.END)
            
            p = int(entries["p"].get())
            g = int(entries["g"].get())
            x = int(entries["x"].get())
            message = message_text.get("1.0", tk.END).strip()
            
            # Ochiq kalit
            y = mod_pow(g, x, p)
            
            result_text.insert(tk.END, "=" * 58 + "\n")
            result_text.insert(tk.END, "EL-GAMAL ELEKTRON RAQAMLI IMZO\n")
            result_text.insert(tk.END, "=" * 58 + "\n\n")
            
            # Kalitlar
            result_text.insert(tk.END, "1. KALIT GENERATSIYASI:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   p = {p} (tub son)\n")
            result_text.insert(tk.END, f"   g = {g} (primitiv ildiz)\n")
            result_text.insert(tk.END, f"   x = {x} (maxfiy kalit, 1 < x < p-1)\n")
            result_text.insert(tk.END, f"   y = g^x mod p = {g}^{x} mod {p} = {y}\n")
            result_text.insert(tk.END, f"\n   Ochiq kalit: (p, g, y)\n")
            result_text.insert(tk.END, f"   Maxfiy kalit: x = {x}\n\n")
            
            # Hash
            h = hash_message(message)
            h_mod = h % (p - 1)
            result_text.insert(tk.END, "2. XABAR VA HASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Xabar: \"{message}\"\n")
            result_text.insert(tk.END, f"   Hash mod (p-1): {h_mod}\n\n")
            
            # Tasodifiy k
            k = random.randint(2, p - 2)
            while gcd(k, p - 1) != 1:
                k = random.randint(2, p - 2)
            
            # Imzolash
            r = mod_pow(g, k, p)
            k_inv = mod_inverse(k, p - 1)
            s = (k_inv * (h_mod - x * r)) % (p - 1)
            
            result_text.insert(tk.END, "3. IMZOLASH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Tasodifiy k = {k} (gcd(k,p-1)=1)\n")
            result_text.insert(tk.END, f"   r = g^k mod p = {r}\n")
            result_text.insert(tk.END, f"   s = k⁻¹(H - xr) mod (p-1) = {s}\n")
            result_text.insert(tk.END, f"\n   Imzo: (r={r}, s={s})\n\n")
            
            # Tekshirish
            left = mod_pow(g, h_mod, p)
            right = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
            
            result_text.insert(tk.END, "4. IMZONI TEKSHIRISH:\n")
            result_text.insert(tk.END, "-" * 58 + "\n")
            result_text.insert(tk.END, f"   Chap tomon: g^H mod p = {left}\n")
            result_text.insert(tk.END, f"   O'ng tomon: (y^r × r^s) mod p = {right}\n")
            result_text.insert(tk.END, f"\n   Natija: ")
            
            if left == right:
                result_text.insert(tk.END, "✓ IMZO TO'G'RI!\n", "success")
                result_text.tag_config("success", foreground="#4ade80")
            else:
                result_text.insert(tk.END, "✗ IMZO NOTO'G'RI!\n", "error")
                result_text.tag_config("error", foreground="#f87171")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik: {str(e)}")
    
    # Tozalash funksiyasi
    def clear_result():
        result_text.delete("1.0", tk.END)
    
    # Buttonlar frame
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=(0, 20))
    
    # Imzolash buttoni
    sign_btn = tk.Button(
        button_frame,
        text="Imzolash va Tekshirish",
        command=rsa_signature if algorithm == "rsa" else (dsa_signature if algorithm == "dsa" else elgamal_signature),
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2",
        activebackground="#c93850"
    )
    sign_btn.pack(side="left", padx=5)
    
    # Tozalash buttoni
    clear_btn = tk.Button(
        button_frame,
        text="Tozalash",
        command=clear_result,
        bg=button_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2"
    )
    clear_btn.pack(side="left", padx=5)