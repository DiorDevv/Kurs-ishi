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
        self.button_color = "#16213e"
        self.button_hover = "#0f3460"
        self.text_color = "#eee"
        self.accent_color = "#e94560"
        
        self.root.configure(bg=self.bg_color)
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
    
    def create_styled_button(self, parent, text, command, row, pady=10):
        """Stilizatsiyalangan button yaratish"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 11),
            relief=tk.FLAT,
            padx=20,
            pady=15,
            cursor="hand2",
            activebackground=self.button_hover,
            activeforeground=self.text_color,
            bd=0,
            highlightthickness=0
        )
        btn.grid(row=row, column=0, pady=pady, padx=40, sticky="ew")
        
        # Hover effekti
        btn.bind("<Enter>", lambda e: btn.config(bg=self.button_hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.button_color))
        
        return btn
    
    def show_main_menu(self):
        """Asosiy menyu"""
        self.clear_window()
        
        # Sarlavha
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(pady=30)
        
        title = tk.Label(
            title_frame,
            text="Kriptografik Algoritmlar",
            font=("Segoe UI", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack()
        
        subtitle = tk.Label(
            title_frame,
            text="Algoritmni tanlang",
            font=("Segoe UI", 12),
            bg=self.bg_color,
            fg=self.text_color
        )
        subtitle.pack(pady=(5, 0))
        
        # Buttonlar frame
        btn_frame = tk.Frame(self.root, bg=self.bg_color)
        btn_frame.pack(expand=True, fill="both", padx=50, pady=(10, 10))
        btn_frame.grid_columnconfigure(0, weight=1)
        
        # Algoritmlar ro'yxati
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
            self.create_styled_button(btn_frame, text, command, i, pady=6)
        
        # Chiqish button
        exit_btn = tk.Button(
            self.root,
            text="Chiqish",
            command=self.root.quit,
            bg=self.accent_color,
            fg=self.text_color,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor="hand2"
        )
        exit_btn.pack(pady=(0, 15))
    
    def show_prng_menu(self):
        """PRNG turlarini tanlash"""
        self.clear_window()
        
        # Orqaga button
        back_btn = tk.Button(
            self.root,
            text="← Orqaga",
            command=self.show_main_menu,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2"
        )
        back_btn.place(x=20, y=20)
        
        # Sarlavha
        title = tk.Label(
            self.root,
            text="Pseudo Tasodifiy Generatorlar",
            font=("Segoe UI", 20, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=40)
        
        # Buttonlar
        btn_frame = tk.Frame(self.root, bg=self.bg_color)
        btn_frame.pack(expand=True, pady=30)
        btn_frame.grid_columnconfigure(0, weight=1)
        
        types = [
            ("Elementar Generatorlar", self.show_elementary_menu),
            ("Murakkab Generatorlar", self.show_complex_menu),
            ("Siljitish Registrli Generatorlar", self.show_shift_menu)
        ]
        
        for i, (text, command) in enumerate(types):
            self.create_styled_button(btn_frame, text, command, i, pady=15)
    

    
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
        back_btn = tk.Button(
            self.root,
            text="← Orqaga",
            command=back_command,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2"
        )
        back_btn.place(x=20, y=20)
        
        title = tk.Label(
            self.root,
            text=title_text,
            font=("Segoe UI", 18, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=50)
        
        btn_frame = tk.Frame(self.root, bg=self.bg_color)
        btn_frame.pack(expand=True, pady=20)
        btn_frame.grid_columnconfigure(0, weight=1)
        
        for i, (text, command) in enumerate(buttons):
            self.create_styled_button(btn_frame, text, command, i, pady=12)
    
    def show_algorithm(self, algo_type, subtype):
        """Algoritm oynasini ko'rsatish"""
        self.clear_window()
        
        # Bu yerda prng moduli ishlatiladi
        prng.show_prng_interface(self.root, algo_type, subtype, 
                                 self.show_prng_menu, self.bg_color, 
                                 self.button_color, self.text_color, 
                                 self.accent_color)
    
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
        
        back_btn = tk.Button(
            self.root,
            text="← Orqaga",
            command=self.show_main_menu,
            bg=self.button_color,
            fg=self.text_color,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2"
        )
        back_btn.place(x=20, y=20)
        
        label = tk.Label(
            self.root,
            text=f"{title}\n\n(Tez kunda qo'shiladi)",
            font=("Segoe UI", 16),
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