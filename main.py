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
        self.root.resizable(True, True)

        # Maksimal qilish (Ubuntu)
        try:
            self.root.state("zoomed")
        except Exception:
            pass

        # ====== RANGLAR (SIZ AYTGANDAY) ======
        self.bg_color = "#0b0b0f"        # ORQA FON QORA
        self.card_color = "#10101a"      # card qoraroq
        self.border_color = "#1e2033"    # border

        self.button_color = "#0a2a5a"    # TO'Q KO'K
        self.button_hover = "#103a7a"    # hover (biroz ochroq ko'k)
        self.text_color = "#f2f2f2"
        self.accent_color = "#ff4d6d"    # sarlavha accent

        self.root.configure(bg=self.bg_color)

        # ====== FONTLAR (KATTA) ======
        self.title_font = ("Segoe UI", 32, "bold")
        self.sub_title_font = ("Segoe UI", 16)
        self.btn_font = ("Segoe UI", 20, "bold")   # BUTTON TEXT KATTA

        self.show_main_menu()

    # ---------------- CORE ----------------
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # ---------------- UI HELPERS ----------------
    def make_card(self, parent, title_text, pady=(0, 0)):
        outer = tk.Frame(parent, bg=self.border_color)
        outer.pack(fill="both", expand=True, pady=pady)

        inner = tk.Frame(outer, bg=self.card_color)
        inner.pack(fill="both", expand=True, padx=2, pady=2)

        header = tk.Label(
            inner,
            text=title_text,
            font=("Segoe UI", 18, "bold"),
            bg=self.card_color,
            fg=self.text_color
        )
        header.pack(anchor="w", padx=20, pady=(16, 10))

        body = tk.Frame(inner, bg=self.card_color)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        return body

    def create_nav_button(self, text, command):
        btn = tk.Button(
            self.root,
            text=text,
            command=command,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 14, "bold"),
            relief=tk.FLAT,
            padx=18,
            pady=12,
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

    def create_styled_button(self, parent, text, command, row, col=0, colspan=1, padx=18, pady=18):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.button_color,
            fg=self.text_color,
            font=self.btn_font,
            relief=tk.FLAT,
            padx=38,      # tugma kattaroq
            pady=26,      # tugma kattaroq
            cursor="hand2",
            activebackground=self.button_hover,
            activeforeground=self.text_color,
            bd=0,
            highlightthickness=0
        )
        btn.grid(row=row, column=col, columnspan=colspan, padx=padx, pady=pady, sticky="nsew")
        btn.bind("<Enter>", lambda e: btn.config(bg=self.button_hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.button_color))
        return btn

    def build_two_col_menu(self, title_text, subtitle_text, card_title, items, back_command):
        """
        items: list of (text, command)
        """
        self.clear_window()
        self.create_nav_button("← Orqaga", back_command)

        tk.Label(
            self.root,
            text=title_text,
            font=("Segoe UI", 28, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        ).pack(pady=(70, 12))

        if subtitle_text:
            tk.Label(
                self.root,
                text=subtitle_text,
                font=("Segoe UI", 16),
                bg=self.bg_color,
                fg=self.text_color
            ).pack(pady=(0, 16))

        content = tk.Frame(self.root, bg=self.bg_color)
        content.pack(fill="both", expand=True, padx=70, pady=(0, 20))

        card_body = self.make_card(content, card_title)

        grid = tk.Frame(card_body, bg=self.card_color)
        grid.pack(fill="both", expand=True)

        grid.grid_columnconfigure(0, weight=1, uniform="col")
        grid.grid_columnconfigure(1, weight=1, uniform="col")

        rows_needed = (len(items) + 1) // 2
        for r in range(rows_needed):
            grid.grid_rowconfigure(r, weight=1)

        for i, (text, cmd) in enumerate(items):
            r = i // 2
            c = i % 2

            is_last = (i == len(items) - 1)
            if is_last and (len(items) % 2 == 1):
                self.create_styled_button(grid, text, cmd, row=r, col=0, colspan=2)
            else:
                self.create_styled_button(grid, text, cmd, row=r, col=c, colspan=1)

    # ---------------- MAIN MENU ----------------
    def show_main_menu(self):
        self.clear_window()

        header = tk.Frame(self.root, bg=self.bg_color)
        header.pack(fill="x", pady=(30, 10))

        tk.Label(
            header,
            text="Kriptografik Algoritmlar",
            font=self.title_font,
            bg=self.bg_color,
            fg=self.accent_color
        ).pack()

        tk.Label(
            header,
            text="4 ta bo‘lim: ERI, PTRR, SHA, Kalit generatsiya",
            font=self.sub_title_font,
            bg=self.bg_color,
            fg=self.text_color
        ).pack(pady=(8, 0))

        main_area = tk.Frame(self.root, bg=self.bg_color)
        main_area.pack(fill="both", expand=True, padx=70, pady=20)

        card = self.make_card(main_area, "📌 Asosiy bo‘limlar")

        grid = tk.Frame(card, bg=self.card_color)
        grid.pack(fill="both", expand=True)

        grid.grid_columnconfigure(0, weight=1, uniform="col")
        grid.grid_columnconfigure(1, weight=1, uniform="col")
        grid.grid_rowconfigure(0, weight=1)
        grid.grid_rowconfigure(1, weight=1)

        sections = [
            ("🔏 ERI — Elektron Raqamli Imzo", self.show_eri_section),
            ("🎲 PTRR — Pseudo Tasodifiy Generatorlar", self.show_prng_menu),
            ("🧾 SHA — Hash Funksiyalari", self.show_sha_section),
            ("🔑 Kalit Generatsiya — Shifrlash & Protokollar", self.show_keygen_section),
        ]

        for i, (text, command) in enumerate(sections):
            r = i // 2
            c = i % 2
            self.create_styled_button(grid, text, command, row=r, col=c)

        # Exit
        footer = tk.Frame(self.root, bg=self.bg_color)
        footer.pack(fill="x", pady=(0, 22))

        exit_btn = tk.Button(
            footer,
            text="🚪 Chiqish",
            command=self.root.quit,
            bg=self.accent_color,
            fg=self.text_color,
            font=("Segoe UI", 16, "bold"),
            relief=tk.FLAT,
            padx=44,
            pady=16,
            cursor="hand2",
            activebackground="#e03a5b",
            activeforeground=self.text_color,
            bd=0,
            highlightthickness=0
        )
        exit_btn.pack()
        exit_btn.bind("<Enter>", lambda e: exit_btn.config(bg="#e03a5b"))
        exit_btn.bind("<Leave>", lambda e: exit_btn.config(bg=self.accent_color))

    # ---------------- 1) ERI ----------------
    def show_eri_section(self):
        items = [
            ("✍️ DSA (Digital Signature Algorithm)", lambda: self.show_signature("dsa")),
            ("🧾 El-Gamal Signature", lambda: self.show_signature("elgamal")),
            ("🔐 RSA Signature", lambda: self.show_signature("rsa")),
        ]
        self.build_two_col_menu(
            title_text="🔏 ERI — Elektron Raqamli Imzo",
            subtitle_text="Imzo algoritmini tanlang",
            card_title="📌 ERI Variantlar",
            items=items,
            back_command=self.show_main_menu
        )

    def show_signature(self, algorithm):
        self.clear_window()
        digital_signature.show_signature_interface(
            self.root, algorithm, self.show_eri_section, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    # ---------------- 2) PTRR ----------------
    def show_prng_menu(self):
        items = [
            ("🧩 Elementar Generatorlar", self.show_elementary_menu),
            ("🧠 Murakkab Generatorlar", self.show_complex_menu),
            ("📡 Siljitish Registrli Generatorlar", self.show_shift_menu),
        ]
        self.build_two_col_menu(
            title_text="🎲 PTRR — Pseudo Tasodifiy Generatorlar",
            subtitle_text="Generator turini tanlang",
            card_title="⚙️ PTRR Turlari",
            items=items,
            back_command=self.show_main_menu
        )

    def show_elementary_menu(self):
        items = [
            ("➗ Chiziqli", lambda: self.show_algorithm("elementary", "linear")),
            ("➕ Nochiziqli", lambda: self.show_algorithm("elementary", "nonlinear")),
        ]
        self.build_two_col_menu(
            title_text="🧩 Elementar Generatorlar",
            subtitle_text="Turini tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_prng_menu
        )

    def show_complex_menu(self):
        items = [
            ("🔐 RSA", lambda: self.show_algorithm("complex", "rsa")),
            ("🎲 BBS", lambda: self.show_algorithm("complex", "bbs")),
            ("🧠 Blum-Micali", lambda: self.show_algorithm("complex", "blum_micali")),
        ]
        self.build_two_col_menu(
            title_text="🧠 Murakkab Generatorlar",
            subtitle_text="Turini tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_prng_menu
        )

    def show_shift_menu(self):
        items = [
            ("📡 A5/1 Algoritmi", lambda: self.show_algorithm("shift", "a51")),
        ]
        self.build_two_col_menu(
            title_text="📡 Siljitish Registrli Generatorlar",
            subtitle_text="Algoritmni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_prng_menu
        )

    def show_algorithm(self, algo_type, subtype):
        self.clear_window()
        prng.show_prng_interface(
            self.root, algo_type, subtype,
            self.show_prng_menu, self.show_main_menu, self.bg_color,
            self.button_color, self.text_color,
            self.accent_color
        )

    # ---------------- 3) SHA ----------------
    def show_sha_section(self):
        items = [
            ("🟠 MD5", lambda: self.show_hash_algo("md5")),
            ("🔵 SHA-1", lambda: self.show_hash_algo("sha1")),
            ("🟣 SHA-256", lambda: self.show_hash_algo("sha256")),
            ("🟢 SHA-512", lambda: self.show_hash_algo("sha512")),
        ]
        self.build_two_col_menu(
            title_text="🧾 SHA — Hash Funksiyalari",
            subtitle_text="Hash algoritmini tanlang",
            card_title="📌 Hash Variantlar",
            items=items,
            back_command=self.show_main_menu
        )

    def show_hash_algo(self, algorithm):
        self.clear_window()
        hash_functions.show_hash_interface(
            self.root, algorithm, self.show_sha_section, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    # ---------------- 4) KALIT GENERATSIYA ----------------
    def show_keygen_section(self):
        items = [
            ("🧊 Simmetrik Shifrlash", self.show_symmetric),
            ("🌊 Oqimli Shifrlash", self.show_stream),
            ("🛰️ Assimetrik Shifrlash", self.show_asymmetric),
            ("🛡️ Autentifikatsiya", self.show_auth),
        ]
        self.build_two_col_menu(
            title_text="🔑 Kalit Generatsiya",
            subtitle_text="Bo‘limni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_main_menu
        )

    def show_symmetric(self):
        items = [
            ("🔒 AES", lambda: self.show_cipher("aes")),
            ("🐡 Blowfish", lambda: self.show_cipher("blowfish")),
            ("🧱 CAST-128", lambda: self.show_cipher("cast")),
        ]
        self.build_two_col_menu(
            title_text="🧊 Simmetrik Shifrlash",
            subtitle_text="Algoritmni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_keygen_section
        )

    def show_cipher(self, algorithm):
        self.clear_window()
        symmetric.show_symmetric_interface(
            self.root, algorithm, self.show_symmetric, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_stream(self):
        items = [
            ("🌊 RC4", lambda: self.show_stream_cipher("rc4")),
            ("📡 A5/1", lambda: self.show_stream_cipher("a51")),
        ]
        self.build_two_col_menu(
            title_text="🌊 Oqimli Shifrlash",
            subtitle_text="Algoritmni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_keygen_section
        )

    def show_stream_cipher(self, algorithm):
        self.clear_window()
        stream_cipher.show_stream_interface(
            self.root, algorithm, self.show_stream, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_asymmetric(self):
        items = [
            ("🛰️ RSA", lambda: self.show_asymmetric_cipher("rsa")),
            ("📨 El-Gamal", lambda: self.show_asymmetric_cipher("elgamal")),
        ]
        self.build_two_col_menu(
            title_text="🛰️ Assimetrik Shifrlash",
            subtitle_text="Algoritmni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_keygen_section
        )

    def show_asymmetric_cipher(self, algorithm):
        self.clear_window()
        asymmetric.show_asymmetric_interface(
            self.root, algorithm, self.show_asymmetric, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def show_auth(self):
        items = [
            ("🛡️ Challenge-Response", lambda: self.show_auth_protocol("challenge_response")),
            ("🔁 Needham-Schroeder", lambda: self.show_auth_protocol("needham_schroeder")),
            ("🎟️ Kerberos", lambda: self.show_auth_protocol("kerberos")),
        ]
        self.build_two_col_menu(
            title_text="🛡️ Autentifikatsiya",
            subtitle_text="Protokolni tanlang",
            card_title="📌 Variantlar",
            items=items,
            back_command=self.show_keygen_section
        )

    def show_auth_protocol(self, protocol):
        self.clear_window()
        authentication.show_auth_interface(
            self.root, protocol, self.show_auth, self.show_main_menu,
            self.bg_color, self.button_color, self.text_color, self.accent_color
        )

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    CryptoApp().run()