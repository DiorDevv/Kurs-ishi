import tkinter as tk
from tkinter import ttk
import sys
import os

# Algoritm modullari import qilish
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from algorithms import prng
from algorithms import digital_signature
from algorithms import symmetric
from algorithms import hash_functions
from algorithms import stream_cipher
from algorithms import asymmetric
from algorithms import authentication


class CryptoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Kriptografik Algoritmlar Tadqiqoti")
        self.root.geometry("1200x820")
        self.root.resizable(False, False)

        # Markazga joylashtirish
        self.center_window(1200, 820)

        # Ranglar va stillar
        self.bg_color = "#1a1a2e"
        self.card_color = "#141428"      # NEW (dizayn uchun)
        self.border_color = "#2a2a4a"    # NEW (dizayn uchun)

        self.button_color = "#16213e"
        self.button_hover = "#0f3460"
        self.text_color = "#eee"
        self.accent_color = "#e94560"
        self.success_color = "#4ade80"

        self.root.configure(bg=self.bg_color)

        # Default fontlar (dizayn)
        self.base_font = ("Segoe UI", 12)
        self.btn_font = ("Segoe UI", 12, "bold")
        self.title_font = ("Segoe UI", 28, "bold")
        self.sub_title_font = ("Segoe UI", 13)

        self.show_main_menu()

    def center_window(self, width, height):
        """Oynani ekran markaziga joylashtirish"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def clear_window(self):
        """Oynani tozalash"""
        for widget in self.root.winfo_children():
            widget.destroy()

    # ===================== NEW: Card wrapper (faqat dizayn) =====================
    def make_card(self, parent, title_text, pady=(0, 0)):
        outer = tk.Frame(parent, bg=self.border_color)
        outer.pack(fill="x", pady=pady)

        inner = tk.Frame(outer, bg=self.card_color)
        inner.pack(fill="x", padx=2, pady=2)

        header = tk.Label(
            inner,
            text=title_text,
            font=("Segoe UI", 14, "bold"),
            bg=self.card_color,
            fg=self.text_color
        )
        header.pack(anchor="w", padx=18, pady=(14, 8))

        body = tk.Frame(inner, bg=self.card_color)
        body.pack(fill="x", padx=18, pady=(0, 16))
        return body

    # ===================== NEW: Styled nav button (faqat dizayn) =====================
    def create_nav_button(self, text, command):
        btn = tk.Button(
            self.root,
            text=text,
            command=command,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=10,
            cursor="hand2",
            activebackground=self.button_hover,
            activeforeground=self.text_color,
            bd=0,
            highlightthickness=0
        )
        btn.place(x=20, y=20)
        btn.bind("<Enter>", lambda e: btn.config(bg=self.button_hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.button_color))
        return btn

    def create_styled_button(self, parent, text, command, row, pady=10):
        """Stilizatsiyalangan button yaratish"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.button_color,
            fg=self.text_color,
            font=self.btn_font,
            relief=tk.FLAT,
            padx=24,
            pady=18,
            cursor="hand2",
            activebackground=self.button_hover,
            activeforeground=self.text_color,
            bd=0,
            highlightthickness=0
        )
        btn.grid(row=row, column=0, pady=pady, padx=30, sticky="ew")

        # Hover effekti
        btn.bind("<Enter>", lambda e: btn.config(bg=self.button_hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.button_color))

        return btn

    def show_main_menu(self):
        """Asosiy menyu"""
        self.clear_window()

        # Top header (dizayn)
        header = tk.Frame(self.root, bg=self.bg_color)
        header.pack(fill="x", pady=(28, 10))

        title = tk.Label(
            header,
            text="Kriptografik Algoritmlar",
            font=self.title_font,
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack()

        subtitle = tk.Label(
            header,
            text="Algoritmni tanlang (DSA, AES, RSA va boshqalar)",
            font=self.sub_title_font,
            bg=self.bg_color,
            fg=self.text_color
        )
        subtitle.pack(pady=(6, 0))

        # Card ichida buttonlar
        main_area = tk.Frame(self.root, bg=self.bg_color)
        main_area.pack(fill="both", expand=True, padx=60, pady=(10, 10))

        card_body = self.make_card(main_area, "📌 Menyu", pady=(0, 0))

        btn_frame = tk.Frame(card_body, bg=self.card_color)
        btn_frame.pack(fill="both", expand=True)
        btn_frame.grid_columnconfigure(0, weight=1)

        algorithms = [
            ("1. Elektron Raqamli Imzo (DSA, El-Gamal, RSA)", self.show_digital_signature),
            ("2. Simmetrik Shifrlash (Blowfish, CAST, AES)", self.show_symmetric),
            ("3. Pseudo Tasodifiy Generatorlar", self.show_prng_menu),
            ("4. Hash Funksiyalari (MD5, SHA)", self.show_hash),
            ("5. Autentifikatsiyalash Protokollari", self.show_auth),
            ("6. Oqimli Shifrlash (A5/1, RC4)", self.show_stream),
            ("7. Assimetrik Shifrlash (RSA, El-Gamal)", self.show_asymmetric)
        ]

        for i, (text, command) in enumerate(algorithms):
            self.create_styled_button(btn_frame, text, command, i, pady=8)

        # Pastki action bar
        footer = tk.Frame(self.root, bg=self.bg_color)
        footer.pack(fill="x", pady=(0, 18))

        exit_btn = tk.Button(
            footer,
            text="🚪 Chiqish",
            command=self.root.quit,
            bg=self.accent_color,
            fg=self.text_color,
            font=("Segoe UI", 12, "bold"),
            relief=tk.FLAT,
            padx=34,
            pady=12,
            cursor="hand2",
            activebackground="#c93850",
            activeforeground=self.text_color
        )
        exit_btn.pack()
        exit_btn.bind("<Enter>", lambda e: exit_btn.config(bg="#c93850"))
        exit_btn.bind("<Leave>", lambda e: exit_btn.config(bg=self.accent_color))

    def show_prng_menu(self):
        """PRNG turlarini tanlash"""
        self.clear_window()

        self.create_nav_button("← Orqaga", self.show_main_menu)

        title = tk.Label(
            self.root,
            text="Pseudo Tasodifiy Generatorlar",
            font=("Segoe UI", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=(55, 10))

        subtitle = tk.Label(
            self.root,
            text="Generator turini tanlang",
            font=("Segoe UI", 13),
            bg=self.bg_color,
            fg=self.text_color
        )
        subtitle.pack(pady=(0, 14))

        content = tk.Frame(self.root, bg=self.bg_color)
        content.pack(fill="both", expand=True, padx=80, pady=10)

        card_body = self.make_card(content, "⚙️ PRNG Turlari", pady=(0, 0))

        btn_frame = tk.Frame(card_body, bg=self.card_color)
        btn_frame.pack(expand=True)
        btn_frame.grid_columnconfigure(0, weight=1)

        types = [
            ("Elementar Generatorlar", self.show_elementary_menu),
            ("Murakkab Generatorlar", self.show_complex_menu),
            ("Siljitish Registrli Generatorlar", self.show_shift_menu)
        ]

        for i, (text, command) in enumerate(types):
            self.create_styled_button(btn_frame, text, command, i, pady=14)

    def show_elementary_menu(self):
        """Elementar generatorlar - Arduino kodidagi"""
        self.clear_window()
        self.create_submenu("Elementar Generatorlar", [
            ("1. Chiziqli", lambda: self.show_algorithm("elementary", "linear")),
            ("2. Nochiziqli", lambda: self.show_algorithm("elementary", "nonlinear"))
        ], self.show_prng_menu)

    def show_complex_menu(self):
        """Murakkab generatorlar - Arduino kodidagi"""
        self.clear_window()
        self.create_submenu("Murakkab Generatorlar", [
            ("1. RSA", lambda: self.show_algorithm("complex", "rsa")),
            ("2. BBS", lambda: self.show_algorithm("complex", "bbs")),
            ("3. Blyum-Mikali", lambda: self.show_algorithm("complex", "blum_micali"))
        ], self.show_prng_menu)

    def show_shift_menu(self):
        """Siljitish registrli generatorlar - Arduino kodidagi"""
        self.clear_window()
        self.create_submenu("Siljitish Registrli Generatorlar", [
            ("1. A5/1 Algoritmi", lambda: self.show_algorithm("shift", "a51"))
        ], self.show_prng_menu)

    def create_submenu(self, title_text, buttons, back_command):
        """Submenu yaratish"""
        self.create_nav_button("← Orqaga", back_command)

        title = tk.Label(
            self.root,
            text=title_text,
            font=("Segoe UI", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=(55, 10))

        subtitle = tk.Label(
            self.root,
            text="Tanlang",
            font=("Segoe UI", 13),
            bg=self.bg_color,
            fg=self.text_color
        )
        subtitle.pack(pady=(0, 14))

        content = tk.Frame(self.root, bg=self.bg_color)
        content.pack(fill="both", expand=True, padx=80, pady=10)

        card_body = self.make_card(content, "📌 Variantlar", pady=(0, 0))

        btn_frame = tk.Frame(card_body, bg=self.card_color)
        btn_frame.pack(expand=True)
        btn_frame.grid_columnconfigure(0, weight=1)

        for i, (text, command) in enumerate(buttons):
            self.create_styled_button(btn_frame, text, command, i, pady=14)

    def show_algorithm(self, algo_type, subtype):
        """Algoritm oynasini ko'rsatish"""
        self.clear_window()

        # Bu yerda prng moduli ishlatiladi
        prng.show_prng_interface(
            self.root, algo_type, subtype,
            self.show_prng_menu, self.bg_color,
            self.button_color, self.text_color,
            self.accent_color
        )

    # Boshqa algoritmlar uchun funksiyalar
    def show_digital_signature(self):
        """Elektron Raqamli Imzo"""
        self.clear_window()
        self.create_submenu("Elektron Raqamli Imzo", [
            ("DSA (Digital Signature Algorithm)", lambda: self.show_signature("dsa")),
            ("El-Gamal Signature", lambda: self.show_signature("elgamal")),
            ("RSA Signature", lambda: self.show_signature("rsa"))
        ], self.show_main_menu)

    def show_signature(self, algorithm):
        """Imzo algoritmi oynasi"""
        self.clear_window()
        digital_signature.show_signature_interface(
            self.root, algorithm, self.show_digital_signature,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_symmetric(self):
        """Simmetrik Shifrlash"""
        self.clear_window()
        self.create_submenu("Simmetrik Shifrlash", [
            ("AES (Advanced Encryption Standard)", lambda: self.show_cipher("aes")),
            ("Blowfish", lambda: self.show_cipher("blowfish")),
            ("CAST-128", lambda: self.show_cipher("cast"))
        ], self.show_main_menu)

    def show_cipher(self, algorithm):
        """Simmetrik shifrlash oynasi"""
        self.clear_window()
        symmetric.show_symmetric_interface(
            self.root, algorithm, self.show_symmetric,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_hash(self):
        """Hash Funksiyalari"""
        self.clear_window()
        self.create_submenu("Hash Funksiyalari", [
            ("MD5", lambda: self.show_hash_algo("md5")),
            ("SHA-1", lambda: self.show_hash_algo("sha1")),
            ("SHA-256", lambda: self.show_hash_algo("sha256")),
            ("SHA-512", lambda: self.show_hash_algo("sha512"))
        ], self.show_main_menu)

    def show_hash_algo(self, algorithm):
        """Hash algoritmi oynasi"""
        self.clear_window()
        hash_functions.show_hash_interface(
            self.root, algorithm, self.show_hash,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_auth(self):
        """Autentifikatsiyalash Protokollari"""
        self.clear_window()
        self.create_submenu("Autentifikatsiyalash Protokollari", [
            ("Challenge-Response", lambda: self.show_auth_protocol("challenge_response")),
            ("Needham-Schroeder", lambda: self.show_auth_protocol("needham_schroeder")),
            ("Kerberos", lambda: self.show_auth_protocol("kerberos"))
        ], self.show_main_menu)

    def show_auth_protocol(self, protocol):
        """Autentifikatsiya protokoli oynasi"""
        self.clear_window()
        authentication.show_auth_interface(
            self.root, protocol, self.show_auth,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_stream(self):
        """Oqimli Shifrlash"""
        self.clear_window()
        self.create_submenu("Oqimli Shifrlash", [
            ("RC4 (Rivest Cipher 4)", lambda: self.show_stream_cipher("rc4")),
            ("A5/1 Stream Cipher", lambda: self.show_stream_cipher("a51"))
        ], self.show_main_menu)

    def show_stream_cipher(self, algorithm):
        """Oqimli shifrlash oynasi"""
        self.clear_window()
        stream_cipher.show_stream_interface(
            self.root, algorithm, self.show_stream,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_asymmetric(self):
        """Assimetrik Shifrlash"""
        self.clear_window()
        self.create_submenu("Assimetrik Shifrlash", [
            ("RSA (Rivest-Shamir-Adleman)", lambda: self.show_asymmetric_cipher("rsa")),
            ("El-Gamal Encryption", lambda: self.show_asymmetric_cipher("elgamal"))
        ], self.show_main_menu)

    def show_asymmetric_cipher(self, algorithm):
        """Assimetrik shifrlash oynasi"""
        self.clear_window()
        asymmetric.show_asymmetric_interface(
            self.root, algorithm, self.show_asymmetric,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_placeholder(self, title):
        """Placeholder oyna"""
        self.clear_window()

        self.create_nav_button("← Orqaga", self.show_main_menu)

        label = tk.Label(
            self.root,
            text=f"{title}\n\n(Tez kunda qo'shiladi)",
            font=("Segoe UI", 18),
            bg=self.bg_color,
            fg=self.text_color
        )
        label.pack(expand=True)

    def run(self):
        """Ilovani ishga tushirish"""
        self.root.mainloop()


if __name__ == "__main__":
    app = CryptoApp()
    app.run()
