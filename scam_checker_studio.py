"""Scam Message Safety Desk — multi-section Tkinter class project demo.

Run with: python scam_checker_studio.py
Uses only Python's standard library. Analysis is offline and rule-based.
"""

import csv
import re
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog


APP_BG = "#eef2f7"
INK = "#1d2d3f"
MUTED = "#68788a"
NAVY = "#18344f"
RED = "#c83232"
TEAL = "#187c72"
WHITE = "#ffffff"
LINE = "#d7dfe8"

# Each rule contributes points only once. These patterns are simple, visible
# heuristics students can explain; they are not a trained detection model.
RULES = [
    ("Time pressure", 2,
     r"\b(act now|immediately|urgent|right away|within \d+ (hours?|minutes?)|expires today|today|limited time)\b",
     "The message pressures the reader to act quickly."),
    ("Secret or sign-in code request", 4,
     r"\b(send|share|tell|give|reply with|provide|read out)\b.{0,55}\b(password|passcode|pin|otp|one[- ]time code|verification code|security code)\b|\b(password|passcode|pin|otp|one[- ]time code|verification code|security code)\b.{0,45}\b(send|share|tell|give|reply with|provide)\b",
     "A legitimate service should not ask someone to tell them a password or sign-in code."),
    ("Unusual payment method", 3,
     r"\b(gift cards?|bitcoin|cryptocurrency|crypto wallet|wire transfer|western union|moneygram)\b",
     "Gift cards, crypto, and wire transfers can be difficult to reverse."),
    ("Threat or consequence", 2,
     r"\b(arrest\w*|warrant\w*|jail|lawsuit|legal action|account will be (?:closed|frozen|suspended)|lose access)\b",
     "Threats can pressure someone into acting before they verify the claim."),
    ("Remote access request", 3,
     r"\b(teamviewer|anydesk|remote access|screen sharing|install .*support app)\b",
     "Unexpected remote-access requests can give another person control of a device."),
    ("Link included", 1,
     r"\b(?:https?://|www\.)[^\s<>]+|\b[a-z0-9][a-z0-9-]*\.(?:com|org|net|edu|gov|io|co|xyz|info|app)(?:/[^\s<>]*)?",
     "A link appears. The app does not open links or confirm who owns a domain."),
    ("Generic greeting", 1,
     r"\b(dear customer|dear user|hello customer|dear account holder|valued customer)\b",
     "Generic greetings are a weak clue and can also appear in legitimate messages."),
    ("Organization identity claim", 1,
     r"\b(we are(?: from| the)?|this is(?: the)?)(?: your)? (?:bank|irs|police|microsoft|apple|amazon|paypal|google|support team|security team)\b",
     "The sender claims to represent an organization. Check through contact details you find independently."),
]

# These invented examples are for classroom demonstration only.
SAMPLES = [
    {"name": "Personal dinner plan", "channel": "Chat", "expected": "Low",
     "message": "Hey, dinner at 7 tomorrow still works for me. See you then!"},
    {"name": "Parcel tracking update", "channel": "SMS", "expected": "Low",
     "message": "Hi Sam, your parcel has shipped. Track it at https://tracking.example.com/order/4821"},
    {"name": "Bank profile notice", "channel": "Email", "expected": "Medium",
     "message": "Dear Customer, this is your bank. Please review your profile today at www.example.com."},
    {"name": "Password reset reminder", "channel": "Email", "expected": "Medium",
     "message": "Hi Mira, reset your password today at https://accounts.example.com if you requested a change."},
    {"name": "Urgent verification code request", "channel": "SMS", "expected": "High",
     "message": "URGENT: This is your bank. Send us your verification code immediately or your account will be closed. Visit http://example.com"},
    {"name": "Tax payment threat", "channel": "Call transcript", "expected": "High",
     "message": "Your tax account is frozen. Pay the fine immediately using Bitcoin or gift cards, or you will be arrested."},
    {"name": "Expected login code", "channel": "SMS", "expected": "Low",
     "message": "Your verification code is 482913. It expires in 10 minutes. Do not share this code with anyone."},
    {"name": "Remote support request", "channel": "Chat", "expected": "High",
     "message": "We are Microsoft Support. Install AnyDesk immediately so we can fix the virus or your files will be lost."},
]


def analyze_message(message):
    """Match the message against each rule and return clues, score, and band."""
    clues = []
    for name, points, pattern, explanation in RULES:
        searchable = message
        if name == "Secret or sign-in code request":
            # A safety reminder such as "Do not share this code" is not a request.
            sentences = re.split(r"(?<=[.!?])\s+", message)
            searchable = " ".join(
                sentence for sentence in sentences
                if not re.search(r"\b(?:do not|don't|never)\s+share\b", sentence, re.IGNORECASE)
            )
        if re.search(pattern, searchable, re.IGNORECASE):
            clues.append({"name": name, "points": points, "why": explanation})
    score = sum(clue["points"] for clue in clues)
    level = "High" if score >= 6 else "Medium" if score >= 3 else "Low"
    return clues, score, level


class SafetyDesk:
    def __init__(self, root):
        self.root = root
        self.root.title("Message Safety Desk | Scam Message Checker")
        self.root.geometry("1260x850")
        self.root.minsize(980, 700)
        self.root.configure(bg=APP_BG)
        self.root.bind("<Control-Return>", lambda _event: self._analyze())
        self.history = []
        self.last_result = None
        self._configure_style()
        self._build_header()
        self._build_dashboard()
        self._build_tabs()
        self._build_footer()
        self._refresh_stats()

    def _configure_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=APP_BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background="#e1e8f0", foreground=INK,
                        padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", WHITE)],
                  foreground=[("selected", RED)])
        style.configure("Treeview", background=WHITE, fieldbackground=WHITE,
                        foreground=INK, rowheight=29, bordercolor=LINE,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#e8edf3", foreground=INK,
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=6)
        style.map("Treeview", background=[("selected", "#dce9f4")], foreground=[("selected", INK)])
        style.configure("TCombobox", padding=6, font=("Segoe UI", 9))
        style.configure("Horizontal.TProgressbar", troughcolor="#e6ebf1", background=TEAL)

    def _build_header(self):
        bar = tk.Frame(self.root, bg=RED, padx=24, pady=14)
        bar.pack(fill="x")
        left = tk.Frame(bar, bg=RED)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="◈  MESSAGE SAFETY DESK", bg=RED, fg=WHITE,
                 font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(left, text="A local scam-warning demo  ·  explainable rules  ·  no message is uploaded",
                 bg=RED, fg="#ffe6e6", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))
        badge = tk.Label(bar, text="  ⚑  PAUSE BEFORE YOU CLICK  ", bg="#9f2028", fg=WHITE,
                         font=("Segoe UI", 10, "bold"), padx=12, pady=10)
        badge.pack(side="right", padx=(12, 0), pady=4)

    def _build_dashboard(self):
        area = tk.Frame(self.root, bg=APP_BG, padx=18, pady=13)
        area.pack(fill="x")
        self.stat_values = {}
        cards = [
            ("scanned", "Messages scanned", "0", NAVY),
            ("high", "High warning", "0", RED),
            ("clues", "Clues detected", "0", TEAL),
            ("examples", "Demo examples", str(len(SAMPLES)), "#7056a8"),
        ]
        for key, title, value, accent in cards:
            card = tk.Frame(area, bg=WHITE, padx=14, pady=9,
                            highlightbackground=LINE, highlightthickness=1)
            card.pack(side="left", fill="x", expand=True, padx=(0, 9))
            tk.Frame(card, bg=accent, height=3).pack(fill="x", side="top")
            tk.Label(card, text=title.upper(), bg=WHITE, fg=MUTED,
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(7, 0))
            value_label = tk.Label(card, text=value, bg=WHITE, fg=accent,
                                   font=("Segoe UI", 21, "bold"))
            value_label.pack(anchor="w")
            self.stat_values[key] = value_label

    def _build_tabs(self):
        shell = tk.Frame(self.root, bg=APP_BG, padx=18)
        shell.pack(fill="both", expand=True)
        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill="both", expand=True)
        self.scan_tab = tk.Frame(self.tabs, bg=WHITE)
        self.library_tab = tk.Frame(self.tabs, bg=WHITE)
        self.guide_tab = tk.Frame(self.tabs, bg=WHITE)
        self.tabs.add(self.scan_tab, text="  ◉  Message Scanner  ")
        self.tabs.add(self.library_tab, text="  ▤  Example Library  ")
        self.tabs.add(self.guide_tab, text="  ◎  Rules & Scoring  ")
        self._build_scan_tab()
        self._build_library_tab()
        self._build_guide_tab()

    def _build_scan_tab(self):
        tab = self.scan_tab
        tab.grid_columnconfigure(0, weight=6)
        tab.grid_columnconfigure(1, weight=5)
        tab.grid_rowconfigure(1, weight=1)
        top = tk.Frame(tab, bg=WHITE, padx=16, pady=12)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Label(top, text="SCAN A MESSAGE", bg=WHITE, fg=INK,
                 font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(top, text="Choose a demo to scan it now, or paste text and click Analyze", bg=WHITE,
                 fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=14)
        tk.Button(top, text="Export history CSV", command=self._export_csv,
                  bg="#e8edf3", fg=INK, relief="flat", padx=12, pady=7,
                  font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right")

        self._make_card(tab, 1, 0, "MESSAGE INPUT", "Try an example, then inspect the rule matches.")
        self._make_card(tab, 1, 1, "SCAN RESULT", "Risk band, points, and reasons appear here.")
        self.left_card = tab.grid_slaves(row=1, column=0)[0]
        self.right_card = tab.grid_slaves(row=1, column=1)[0]
        self._fill_input_card(self.left_card)
        self._fill_result_card(self.right_card)

        history_box = tk.Frame(tab, bg=WHITE, padx=15, pady=10)
        history_box.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))
        tk.Label(history_box, text="RECENT SCANS", bg=WHITE, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
        columns = ("time", "channel", "level", "score", "preview")
        self.history_tree = ttk.Treeview(history_box, columns=columns, show="headings", height=4)
        for col, title, width in [("time", "Time", 90), ("channel", "Type", 105),
                                  ("level", "Warning", 90), ("score", "Score", 70),
                                  ("preview", "Message preview", 520)]:
            self.history_tree.heading(col, text=title)
            self.history_tree.column(col, width=width, anchor="w" if col == "preview" else "center")
        self.history_tree.pack(fill="x")

    def _make_card(self, parent, row, col, heading, subtitle):
        card = tk.Frame(parent, bg=WHITE, padx=15, pady=12,
                        highlightbackground=LINE, highlightthickness=1)
        card.grid(row=row, column=col, sticky="nsew", padx=(12 if col == 0 else 6, 6 if col == 0 else 12),
                  pady=(0, 11))
        parent.grid_rowconfigure(row, weight=1)
        tk.Label(card, text=heading, bg=WHITE, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(card, text=subtitle, bg=WHITE, fg=MUTED,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 9))
        return card

    def _fill_input_card(self, card):
        tk.Label(card, text="Demo sample", bg=WHITE, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        row = tk.Frame(card, bg=WHITE)
        row.pack(fill="x", pady=(4, 9))
        self.sample_var = tk.StringVar(value="Choose a sample…")
        self.sample_box = ttk.Combobox(row, textvariable=self.sample_var,
                                       values=[s["name"] for s in SAMPLES], state="readonly")
        self.sample_box.pack(side="left", fill="x", expand=True)
        self.sample_box.bind("<<ComboboxSelected>>", self._load_sample)
        tk.Button(row, text="Load", command=self._load_sample, bg="#e8edf3", fg=INK,
                  relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=(6, 0))

        metadata = tk.Frame(card, bg=WHITE)
        metadata.pack(fill="x", pady=(0, 7))
        tk.Label(metadata, text="Message type", bg=WHITE, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
        self.channel_var = tk.StringVar(value="SMS")
        ttk.Combobox(metadata, textvariable=self.channel_var,
                     values=["SMS", "Email", "Chat", "Call transcript", "Other"],
                     state="readonly", width=18).pack(side="right")

        self.message_text = tk.Text(card, height=9, wrap="word", font=("Segoe UI", 10),
                                    bg="#f8fafc", fg=INK, insertbackground=INK,
                                    relief="flat", padx=10, pady=9,
                                    highlightthickness=1, highlightbackground=LINE)
        self.message_text.pack(fill="both", expand=True)
        actions = tk.Frame(card, bg=WHITE)
        actions.pack(fill="x", pady=(10, 0))
        tk.Button(actions, text="  Analyze message  →  ", command=self._analyze,
                  bg=RED, fg=WHITE, activebackground="#a9212b", activeforeground=WHITE,
                  relief="flat", padx=12, pady=9, font=("Segoe UI", 9, "bold"),
                  cursor="hand2").pack(side="left")
        tk.Button(actions, text="Paste", command=self._paste, bg="#e8edf3", fg=INK,
                  relief="flat", padx=12, pady=9, cursor="hand2").pack(side="left", padx=6)
        tk.Button(actions, text="Clear", command=self._clear, bg="#e8edf3", fg=INK,
                  relief="flat", padx=12, pady=9, cursor="hand2").pack(side="left")

    def _fill_result_card(self, card):
        top = tk.Frame(card, bg="#f4f7fa", padx=12, pady=10)
        top.pack(fill="x", pady=(7, 10))
        self.level_label = tk.Label(top, text="WAITING FOR SCAN", bg="#f4f7fa", fg=MUTED,
                                    font=("Segoe UI", 14, "bold"))
        self.level_label.pack(side="left")
        self.score_label = tk.Label(top, text="Score 0", bg="#f4f7fa", fg=INK,
                                    font=("Segoe UI", 10, "bold"))
        self.score_label.pack(side="right")
        self.score_bar = ttk.Progressbar(card, maximum=20, mode="determinate", style="Horizontal.TProgressbar")
        self.score_bar.pack(fill="x", pady=(0, 4))
        tk.Label(card, text="LOW  0–2       MEDIUM  3–5       HIGH  6+", bg=WHITE,
                 fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(1, 9))

        tk.Label(card, text="Detected clues", bg=WHITE, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        columns = ("clue", "points", "reason")
        self.clue_tree = ttk.Treeview(card, columns=columns, show="headings", height=6)
        for col, title, width in [("clue", "Warning sign", 155), ("points", "Pts", 44), ("reason", "Why it matters", 260)]:
            self.clue_tree.heading(col, text=title)
            self.clue_tree.column(col, width=width, anchor="w" if col != "points" else "center")
        self.clue_tree.pack(fill="both", expand=True)

        tk.Label(card, text="Suggested next step", bg=WHITE, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 4))
        self.advice_label = tk.Label(card, text="Analyze a message to get a cautious next step.",
                                     bg="#f4f7fa", fg=INK, wraplength=430,
                                     justify="left", anchor="w", padx=10, pady=9,
                                     font=("Segoe UI", 9))
        self.advice_label.pack(fill="x")

    def _build_library_tab(self):
        tab = self.library_tab
        tab.grid_columnconfigure(0, weight=5)
        tab.grid_columnconfigure(1, weight=6)
        tab.grid_rowconfigure(1, weight=1)
        heading = tk.Frame(tab, bg=WHITE, padx=16, pady=13)
        heading.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Label(heading, text="DEMO CASE LIBRARY", bg=WHITE, fg=INK,
                 font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(heading, text="Select a case to inspect it or load it into the scanner.",
                 bg=WHITE, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=12)

        left = tk.Frame(tab, bg=WHITE, padx=13, pady=11)
        left.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(0, 12))
        right = tk.Frame(tab, bg=WHITE, padx=16, pady=14,
                         highlightbackground=LINE, highlightthickness=1)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(0, 12))
        search_row = tk.Frame(left, bg=WHITE)
        search_row.pack(fill="x", pady=(0, 8))
        tk.Label(search_row, text="Find a case", bg=WHITE, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left")
        self.library_search = tk.StringVar()
        search = ttk.Entry(search_row, textvariable=self.library_search, width=25)
        search.pack(side="right", fill="x", expand=True, padx=(8, 0))
        self.library_search.trace_add("write", lambda *_: self._populate_library())
        self.library_tree = ttk.Treeview(left, columns=("name", "channel", "level"),
                                         show="headings", selectmode="browse")
        for col, title, width in [("name", "Example", 195), ("channel", "Type", 100), ("level", "Band", 80)]:
            self.library_tree.heading(col, text=title)
            self.library_tree.column(col, width=width, anchor="w")
        self.library_tree.pack(fill="both", expand=True)
        self.library_tree.bind("<<TreeviewSelect>>", self._show_case)
        self._populate_library()

        tk.Label(right, text="CASE DETAILS", bg=WHITE, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.case_title = tk.Label(right, text="Choose an example", bg=WHITE, fg=INK,
                                   font=("Segoe UI", 17, "bold"), wraplength=450, justify="left")
        self.case_title.pack(anchor="w", pady=(6, 3))
        self.case_meta = tk.Label(right, text="", bg=WHITE, fg=MUTED, font=("Segoe UI", 9))
        self.case_meta.pack(anchor="w", pady=(0, 10))
        self.case_message = tk.Text(right, height=8, wrap="word", font=("Segoe UI", 10),
                                    bg="#f8fafc", fg=INK, relief="flat", padx=11, pady=10,
                                    state="disabled", highlightthickness=1, highlightbackground=LINE)
        self.case_message.pack(fill="x", pady=(0, 10))
        self.case_clues = tk.Label(right, text="", bg=WHITE, fg=INK, wraplength=450,
                                   justify="left", anchor="w", font=("Segoe UI", 9))
        self.case_clues.pack(fill="x", expand=True, anchor="nw")
        tk.Button(right, text="Load this case in Scanner  →", command=self._use_selected_case,
                  bg=RED, fg=WHITE, relief="flat", padx=12, pady=9,
                  font=("Segoe UI", 9, "bold"), cursor="hand2").pack(anchor="w", pady=(12, 0))

    def _build_guide_tab(self):
        tab = self.guide_tab
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(1, weight=1)
        title = tk.Frame(tab, bg=WHITE, padx=16, pady=13)
        title.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Label(title, text="HOW THE CHECKER WORKS", bg=WHITE, fg=INK,
                 font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(title, text="A transparent rules-and-points model you can explain in your presentation.",
                 bg=WHITE, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        rules_box = tk.Frame(tab, bg=WHITE, padx=15, pady=12,
                             highlightbackground=LINE, highlightthickness=1)
        rules_box.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(0, 12))
        tk.Label(rules_box, text="RULE CATALOG", bg=WHITE, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 7))
        tree = ttk.Treeview(rules_box, columns=("rule", "points", "meaning"), show="headings")
        for col, text, width in [("rule", "Rule", 185), ("points", "Points", 65), ("meaning", "What it checks", 370)]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor="w" if col != "points" else "center")
        for name, points, _pattern, explanation in RULES:
            tree.insert("", "end", values=(name, f"+{points}", explanation))
        tree.pack(fill="both", expand=True)

        explainer = tk.Frame(tab, bg="#f7f9fc", padx=18, pady=16,
                             highlightbackground=LINE, highlightthickness=1)
        explainer.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(0, 12))
        tk.Label(explainer, text="THE ANALYSIS FLOW", bg="#f7f9fc", fg=TEAL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        flow = [
            ("1  Input", "The user pastes a message or chooses an invented example."),
            ("2  Match", "Python checks the text against each regular-expression rule."),
            ("3  Score", "Each matched rule adds its points once; clues are listed."),
            ("4  Explain", "The app shows a Low, Medium, or High band and a cautious next step."),
        ]
        for title_text, detail in flow:
            row = tk.Frame(explainer, bg="#f7f9fc", pady=7)
            row.pack(fill="x")
            tk.Label(row, text=title_text, bg="#f7f9fc", fg=INK,
                     font=("Segoe UI", 10, "bold")).pack(anchor="w")
            tk.Label(row, text=detail, bg="#f7f9fc", fg=MUTED, wraplength=320,
                     justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
        tk.Frame(explainer, bg=LINE, height=1).pack(fill="x", pady=8)
        tk.Label(explainer, text="LIMITATIONS", bg="#f7f9fc", fg=RED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(explainer,
                 text="This is not AI and it does not prove fraud. It never visits links. New scams may evade the rules, while ordinary messages may match a clue. Verify through official contact information you find yourself.",
                 bg="#f7f9fc", fg=INK, wraplength=330, justify="left",
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 0))

    def _build_footer(self):
        tk.Label(self.root,
                 text="CLASS PROJECT DEMO  •  Offline rule matching  •  Do not paste private or sensitive messages",
                 bg=APP_BG, fg=MUTED, font=("Segoe UI", 8), pady=7).pack(fill="x")

    def _load_sample(self, event=None):
        selected = self.sample_var.get()
        sample = next((item for item in SAMPLES if item["name"] == selected), None)
        if sample:
            self.message_text.delete("1.0", "end")
            self.message_text.insert("1.0", sample["message"])
            self.channel_var.set(sample["channel"])
            # Selecting or loading a demo performs the scan immediately so the
            # result panel never appears stuck on its initial waiting state.
            self._analyze()

    def _paste(self):
        try:
            content = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Clipboard empty", "Copy some message text first, then try Paste again.")
            return
        self.message_text.delete("1.0", "end")
        self.message_text.insert("1.0", content)

    def _clear(self):
        self.message_text.delete("1.0", "end")
        self.sample_var.set("Choose a sample…")
        self.level_label.configure(text="WAITING FOR SCAN", fg=MUTED)
        self.score_label.configure(text="Score 0")
        self.score_bar["value"] = 0
        for item in self.clue_tree.get_children():
            self.clue_tree.delete(item)
        self.advice_label.configure(text="Analyze a message to get a cautious next step.", bg="#f4f7fa")

    def _analyze(self):
        message = self.message_text.get("1.0", "end").strip()
        if not message:
            messagebox.showinfo("Message needed", "Paste a message or choose one from the demo examples.")
            return
        clues, score, level = analyze_message(message)
        colors = {"Low": TEAL, "Medium": "#b77912", "High": RED}
        backgrounds = {"Low": "#e7f4ef", "Medium": "#fff4dd", "High": "#fdebec"}
        self.level_label.configure(text=f"{level.upper()} WARNING", fg=colors[level])
        self.level_label.master.configure(bg=backgrounds[level])
        self.level_label.configure(bg=backgrounds[level])
        self.score_label.configure(text=f"Score {score}", bg=backgrounds[level])
        self.score_label.master.configure(bg=backgrounds[level])
        self.score_bar["value"] = min(score, 20)
        for item in self.clue_tree.get_children():
            self.clue_tree.delete(item)
        for clue in clues:
            self.clue_tree.insert("", "end", values=(clue["name"], f"+{clue['points']}", clue["why"]))
        advice = {
            "Low": "Few selected clues matched. This does not prove the message is genuine.",
            "Medium": "Pause and verify the request through an official app, website, or number you find yourself.",
            "High": "Do not click links, share codes, install software, or send money. Contact the organization independently.",
        }[level]
        self.advice_label.configure(text=advice, bg=backgrounds[level])
        record = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "channel": self.channel_var.get(), "level": level, "score": score,
            "message": message, "clues": "; ".join(c["name"] for c in clues),
        }
        self.history.insert(0, record)
        self.history_tree.insert("", 0, values=(record["time"], record["channel"],
                                                 record["level"], score,
                                                 message.replace("\n", " ")[:90]))
        self.last_result = record
        self._refresh_stats()

    def _refresh_stats(self):
        self.stat_values["scanned"].configure(text=str(len(self.history)))
        self.stat_values["high"].configure(text=str(sum(x["level"] == "High" for x in self.history)))
        self.stat_values["clues"].configure(text=str(sum(len(x["clues"].split("; ")) if x["clues"] else 0 for x in self.history)))

    def _populate_library(self):
        if not hasattr(self, "library_tree"):
            return
        query = self.library_search.get().strip().lower()
        for item in self.library_tree.get_children():
            self.library_tree.delete(item)
        for index, sample in enumerate(SAMPLES):
            if query and query not in (sample["name"] + sample["channel"] + sample["expected"] + sample["message"]).lower():
                continue
            self.library_tree.insert("", "end", iid=str(index),
                                     values=(sample["name"], sample["channel"], sample["expected"]))

    def _selected_sample(self):
        selection = self.library_tree.selection()
        return SAMPLES[int(selection[0])] if selection else None

    def _show_case(self, event=None):
        sample = self._selected_sample()
        if not sample:
            return
        clues, score, actual = analyze_message(sample["message"])
        self.case_title.configure(text=sample["name"])
        self.case_meta.configure(text=f"{sample['channel']}  ·  Expected demo band: {sample['expected']}  ·  Rule result: {actual} ({score} points)")
        self.case_message.configure(state="normal")
        self.case_message.delete("1.0", "end")
        self.case_message.insert("1.0", sample["message"])
        self.case_message.configure(state="disabled")
        clue_text = "Matched clues: " + (", ".join(c["name"] for c in clues) if clues else "none")
        self.case_clues.configure(text=clue_text)

    def _use_selected_case(self):
        sample = self._selected_sample()
        if not sample:
            messagebox.showinfo("Choose a case", "Select an example from the library first.")
            return
        self.message_text.delete("1.0", "end")
        self.message_text.insert("1.0", sample["message"])
        self.channel_var.set(sample["channel"])
        self.sample_var.set(sample["name"])
        self.tabs.select(self.scan_tab)

    def _export_csv(self):
        if not self.history:
            messagebox.showinfo("No scan history", "Analyze at least one message before exporting.")
            return
        path = filedialog.asksaveasfilename(
            title="Export scan history", defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")], initialfile="message_safety_scan_history.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=["time", "channel", "level", "score", "clues", "message"])
            writer.writeheader()
            writer.writerows(self.history)
        messagebox.showinfo("Export complete", "Your scan history was saved as a CSV file.")


if __name__ == "__main__":
    app_root = tk.Tk()
    SafetyDesk(app_root)
    app_root.mainloop()
