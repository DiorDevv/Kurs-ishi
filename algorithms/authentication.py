import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import hashlib
import hmac
import random
import time
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def show_auth_interface(root, protocol, back_command, bg_color, button_color, text_color, accent_color):
    """Autentifikatsiyalash protokollari interfeysi"""
    
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
    
    # Protokol ma'lumotlari
    protocol_info = {
        "challenge_response": {
            "name": "Challenge-Response Protocol",
            "description": "Server tasodifiy challenge yuboradi, client hash javob beradi"
        },
        "needham_schroeder": {
            "name": "Needham-Schroeder Protocol",
            "description": "Simmetrik kalit bilan markaziy server orqali autentifikatsiya"
        },
        "kerberos": {
            "name": "Kerberos Protocol (soddalashtirilgan)",
            "description": "Ticket asosida autentifikatsiya tizimi"
        }
    }
    
    info = protocol_info[protocol]
    
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
    
    # Natija frame
    result_frame = tk.LabelFrame(
        container,
        text="Protokol Jarayoni",
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg=text_color,
        relief=tk.FLAT,
        bd=2
    )
    result_frame.pack(fill="both", expand=True)
    
    # Sozlamalar
    settings_inner = tk.Frame(settings_frame, bg=bg_color)
    settings_inner.pack(fill="x", padx=10, pady=10)
    
    if protocol == "challenge_response":
        # Username va password
        user_label = tk.Label(
            settings_inner,
            text="Username:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        user_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        user_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=20
        )
        user_entry.insert(0, "alice")
        user_entry.grid(row=0, column=1, padx=(0, 20))
        
        pass_label = tk.Label(
            settings_inner,
            text="Password:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        pass_label.grid(row=0, column=2, padx=(0, 10), sticky="w")
        
        pass_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=20,
            show="*"
        )
        pass_entry.insert(0, "secret123")
        pass_entry.grid(row=0, column=3)
        
    elif protocol == "needham_schroeder":
        # Alice, Bob, Server kalitlari
        alice_label = tk.Label(
            settings_inner,
            text="Alice:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        alice_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        alice_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=15
        )
        alice_entry.insert(0, "Alice")
        alice_entry.grid(row=0, column=1, padx=(0, 15))
        
        bob_label = tk.Label(
            settings_inner,
            text="Bob:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        bob_label.grid(row=0, column=2, padx=(0, 10), sticky="w")
        
        bob_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=15
        )
        bob_entry.insert(0, "Bob")
        bob_entry.grid(row=0, column=3)
        
    elif protocol == "kerberos":
        # Client va Service
        client_label = tk.Label(
            settings_inner,
            text="Client:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        client_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        client_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=15
        )
        client_entry.insert(0, "Alice")
        client_entry.grid(row=0, column=1, padx=(0, 15))
        
        service_label = tk.Label(
            settings_inner,
            text="Service:",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=text_color
        )
        service_label.grid(row=0, column=2, padx=(0, 10), sticky="w")
        
        service_entry = tk.Entry(
            settings_inner,
            font=("Consolas", 9),
            bg=button_color,
            fg=text_color,
            insertbackground=text_color,
            relief=tk.FLAT,
            bd=2,
            width=15
        )
        service_entry.insert(0, "FileServer")
        service_entry.grid(row=0, column=3)
    
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
    
    # Challenge-Response protokoli
    def challenge_response_auth():
        try:
            result_text.delete("1.0", tk.END)
            
            username = user_entry.get().strip()
            password = pass_entry.get().strip()
            
            if not username or not password:
                messagebox.showerror("Xato", "Username va Password kiriting!")
                return
            
            result_text.insert(tk.END, "=" * 70 + "\n")
            result_text.insert(tk.END, "CHALLENGE-RESPONSE AUTENTIFIKATSIYA\n")
            result_text.insert(tk.END, "=" * 70 + "\n\n")
            
            # 1. Client → Server: Username
            result_text.insert(tk.END, "1️⃣ CLIENT → SERVER: Username so'rovi\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Client: \"Men {username}man\"\n")
            result_text.insert(tk.END, f"   Server: Username qabul qilindi\n\n")
            
            # 2. Server generates challenge
            challenge = random.randint(100000, 999999)
            result_text.insert(tk.END, "2️⃣ SERVER → CLIENT: Challenge yuborish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Server tasodifiy challenge generatsiya qildi: {challenge}\n")
            result_text.insert(tk.END, f"   Server: \"Challenge = {challenge}\"\n\n")
            
            # 3. Client computes response
            result_text.insert(tk.END, "3️⃣ CLIENT: Response hisoblash\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            message = f"{username}:{challenge}:{password}"
            response = hashlib.sha256(message.encode()).hexdigest()
            result_text.insert(tk.END, f"   Client formulasi: SHA256(username:challenge:password)\n")
            result_text.insert(tk.END, f"   Message: {message}\n")
            result_text.insert(tk.END, f"   Response: {response[:40]}...\n\n")
            
            # 4. Client → Server: Response
            result_text.insert(tk.END, "4️⃣ CLIENT → SERVER: Response yuborish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Client: \"Response = {response[:40]}...\"\n\n")
            
            # 5. Server verifies
            result_text.insert(tk.END, "5️⃣ SERVER: Response tekshirish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            # Server'da saqlanган password (bizda bir xil)
            stored_password = password
            expected_message = f"{username}:{challenge}:{stored_password}"
            expected_response = hashlib.sha256(expected_message.encode()).hexdigest()
            result_text.insert(tk.END, f"   Server kutilgan response hisoblaydi:\n")
            result_text.insert(tk.END, f"   Expected: {expected_response[:40]}...\n")
            result_text.insert(tk.END, f"   Received: {response[:40]}...\n\n")
            
            if response == expected_response:
                result_text.insert(tk.END, "   ✓ AUTENTIFIKATSIYA MUVAFFAQIYATLI!\n", "success")
                result_text.tag_config("success", foreground="#4ade80")
            else:
                result_text.insert(tk.END, "   ✗ AUTENTIFIKATSIYA MUVAFFAQIYATSIZ!\n", "error")
                result_text.tag_config("error", foreground="#f87171")
            
            result_text.insert(tk.END, "\n")
            result_text.insert(tk.END, "XAVFSIZLIK XUSUSIYATLARI:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, "• Password tarmoqda yuborilmaydi\n")
            result_text.insert(tk.END, "• Har safar yangi challenge ishlatiladi\n")
            result_text.insert(tk.END, "• Replay attack'dan himoyalangan\n")
            result_text.insert(tk.END, "• Hash funksiya qaytarib bo'lmaydigan\n")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik:\n{str(e)}")
    
    # Needham-Schroeder protokoli
    def needham_schroeder_auth():
        try:
            result_text.delete("1.0", tk.END)
            
            alice_name = alice_entry.get().strip()
            bob_name = bob_entry.get().strip()
            
            if not alice_name or not bob_name:
                messagebox.showerror("Xato", "Alice va Bob nomlarini kiriting!")
                return
            
            result_text.insert(tk.END, "=" * 70 + "\n")
            result_text.insert(tk.END, "NEEDHAM-SCHROEDER PROTOCOL\n")
            result_text.insert(tk.END, "=" * 70 + "\n\n")
            
            # Kalitlar generatsiya
            K_as = get_random_bytes(16)  # Alice-Server shared key
            K_bs = get_random_bytes(16)  # Bob-Server shared key
            K_ab = get_random_bytes(16)  # Alice-Bob session key
            
            result_text.insert(tk.END, "DASTLABKI KALITLAR:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"K_AS (Alice-Server): {binascii.hexlify(K_as).decode()[:32]}...\n")
            result_text.insert(tk.END, f"K_BS (Bob-Server): {binascii.hexlify(K_bs).decode()[:32]}...\n\n")
            
            # 1. Alice → Server
            nonce_a = random.randint(1000, 9999)
            result_text.insert(tk.END, f"1️⃣ {alice_name} → SERVER\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Alice: \"Men {bob_name} bilan gaplashmoqchiman\"\n")
            result_text.insert(tk.END, f"   Nonce: {nonce_a}\n\n")
            
            # 2. Server → Alice
            result_text.insert(tk.END, f"2️⃣ SERVER → {alice_name}\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Server yangi session key generatsiya qiladi:\n")
            result_text.insert(tk.END, f"   K_AB: {binascii.hexlify(K_ab).decode()[:32]}...\n")
            
            # Ticket for Bob
            ticket_for_bob = f"{alice_name}:{binascii.hexlify(K_ab).decode()[:16]}"
            cipher_bs = AES.new(K_bs, AES.MODE_ECB)
            encrypted_ticket = cipher_bs.encrypt(pad(ticket_for_bob.encode(), 16))
            
            result_text.insert(tk.END, f"\n   Ticket (Bob uchun, K_BS bilan shifrlangan):\n")
            result_text.insert(tk.END, f"   {binascii.hexlify(encrypted_ticket).decode()[:40]}...\n\n")
            
            # 3. Alice → Bob
            result_text.insert(tk.END, f"3️⃣ {alice_name} → {bob_name}\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Alice ticket va K_AB ni Bob'ga yuboradi\n")
            result_text.insert(tk.END, f"   (K_AB bilan shifrlangan)\n\n")
            
            # 4. Bob verifies
            result_text.insert(tk.END, f"4️⃣ {bob_name}: Ticket tekshirish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            decrypted_ticket = unpad(cipher_bs.decrypt(encrypted_ticket), 16).decode()
            result_text.insert(tk.END, f"   Bob ticket'ni deshifrlaydi (K_BS bilan):\n")
            result_text.insert(tk.END, f"   Ticket ichida: {decrypted_ticket}\n")
            result_text.insert(tk.END, f"   ✓ Ticket to'g'ri!\n\n")
            
            result_text.insert(tk.END, "NATIJA:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"✓ {alice_name} va {bob_name} muvaffaqiyatli autentifikatsiya\n", "success")
            result_text.insert(tk.END, f"✓ Ular endi K_AB kaliti bilan xavfsiz muloqot qilishlari mumkin\n", "success")
            result_text.tag_config("success", foreground="#4ade80")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik:\n{str(e)}")
    
    # Kerberos protokoli
    def kerberos_auth():
        try:
            result_text.delete("1.0", tk.END)
            
            client_name = client_entry.get().strip()
            service_name = service_entry.get().strip()
            
            if not client_name or not service_name:
                messagebox.showerror("Xato", "Client va Service nomlarini kiriting!")
                return
            
            result_text.insert(tk.END, "=" * 70 + "\n")
            result_text.insert(tk.END, "KERBEROS AUTENTIFIKATSIYA (SODDALASHTIRILGAN)\n")
            result_text.insert(tk.END, "=" * 70 + "\n\n")
            
            # Kalitlar
            K_client = get_random_bytes(16)  # Client password-dan olingan
            K_tgs = get_random_bytes(16)     # TGS kaliti
            K_service = get_random_bytes(16) # Service kaliti
            
            result_text.insert(tk.END, "TIZIM KOMPONENTLARI:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, "• AS (Authentication Server) - Dastlabki autentifikatsiya\n")
            result_text.insert(tk.END, "• TGS (Ticket Granting Server) - Ticket berish\n")
            result_text.insert(tk.END, f"• Service: {service_name}\n\n")
            
            # 1. Client → AS
            result_text.insert(tk.END, f"1️⃣ {client_name} → AS: TGT so'rash\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Client: \"Men {client_name}, TGT kerak\"\n\n")
            
            # 2. AS → Client: TGT
            K_session_tgs = get_random_bytes(16)
            timestamp = int(time.time())
            lifetime = 28800  # 8 soat
            
            result_text.insert(tk.END, f"2️⃣ AS → {client_name}: TGT berish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Session Key (TGS): {binascii.hexlify(K_session_tgs).decode()[:32]}...\n")
            
            tgt = f"TGT:{client_name}:{timestamp}:{lifetime}"
            cipher_tgs = AES.new(K_tgs, AES.MODE_ECB)
            encrypted_tgt = cipher_tgs.encrypt(pad(tgt.encode(), 16))
            result_text.insert(tk.END, f"   TGT (shifrlangan): {binascii.hexlify(encrypted_tgt).decode()[:40]}...\n\n")
            
            # 3. Client → TGS: Service ticket so'rash
            result_text.insert(tk.END, f"3️⃣ {client_name} → TGS: Service ticket so'rash\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Client: \"Men {service_name} ga kirmoqchiman\"\n")
            result_text.insert(tk.END, f"   TGT va authenticator yuborildi\n\n")
            
            # 4. TGS → Client: Service ticket
            K_session_service = get_random_bytes(16)
            result_text.insert(tk.END, f"4️⃣ TGS → {client_name}: Service ticket berish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Session Key (Service): {binascii.hexlify(K_session_service).decode()[:32]}...\n")
            
            service_ticket = f"Ticket:{client_name}:{service_name}:{timestamp}"
            cipher_service = AES.new(K_service, AES.MODE_ECB)
            encrypted_service_ticket = cipher_service.encrypt(pad(service_ticket.encode(), 16))
            result_text.insert(tk.END, f"   Service Ticket: {binascii.hexlify(encrypted_service_ticket).decode()[:40]}...\n\n")
            
            # 5. Client → Service
            result_text.insert(tk.END, f"5️⃣ {client_name} → {service_name}: Service'ga kirish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"   Client service ticket va authenticator yuboradi\n\n")
            
            # 6. Service verifies
            result_text.insert(tk.END, f"6️⃣ {service_name}: Ticket tekshirish\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            decrypted_ticket = unpad(cipher_service.decrypt(encrypted_service_ticket), 16).decode()
            result_text.insert(tk.END, f"   Service ticket'ni deshifrlaydi:\n")
            result_text.insert(tk.END, f"   {decrypted_ticket}\n")
            result_text.insert(tk.END, f"   ✓ Ticket to'g'ri va hali amal qilmoqda!\n\n")
            
            result_text.insert(tk.END, "NATIJA:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, f"✓ {client_name} muvaffaqiyatli autentifikatsiya qilindi\n", "success")
            result_text.insert(tk.END, f"✓ {service_name} ga kirish huquqi berildi\n", "success")
            result_text.insert(tk.END, f"✓ Session key bilan xavfsiz muloqot\n", "success")
            result_text.tag_config("success", foreground="#4ade80")
            
            result_text.insert(tk.END, "\n\nKERBEROS AFZALLIKLARI:\n")
            result_text.insert(tk.END, "─" * 70 + "\n")
            result_text.insert(tk.END, "• Password tarmoqda yuborilmaydi\n")
            result_text.insert(tk.END, "• Single Sign-On (bir marta login)\n")
            result_text.insert(tk.END, "• Markazlashtirilgan autentifikatsiya\n")
            result_text.insert(tk.END, "• Ticket asosida kirish nazorati\n")
            
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik:\n{str(e)}")
    
    # Tozalash
    def clear_all():
        result_text.delete("1.0", tk.END)
    
    # Buttonlar
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=(5, 15))
    
    if protocol == "challenge_response":
        run_command = challenge_response_auth
        button_text = "Autentifikatsiya Boshlash"
    elif protocol == "needham_schroeder":
        run_command = needham_schroeder_auth
        button_text = "Protokol Ishga Tushirish"
    else:  # kerberos
        run_command = kerberos_auth
        button_text = "Kerberos Autentifikatsiya"
    
    run_btn = tk.Button(
        button_frame,
        text=button_text,
        command=run_command,
        bg=accent_color,
        fg=text_color,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        padx=30,
        pady=10,
        cursor="hand2",
        activebackground="#c93850"
    )
    run_btn.pack(side="left", padx=5)
    
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