# Message Safety Desk

**A second look before the first click.**

Offline · Rule-based · Explainable

A desktop class-project demo that helps users pause and inspect potentially suspicious messages. The app runs entirely offline, uses transparent regular-expression rules, and never uploads any message content.

![Message Safety Desk](docs/preview.png)

---

## Team

| Name                    | Roll Number       |
|-------------------------|-------------------|
| Aadhithya Dhinakar      | RA2511003012399   |
| Sree Monish Sunkara     | RA2511003012352   |
| Shinde Om Arvind        | RA2511003012342   |

---

## Features

- **Message Scanner** – Paste any message or load a built-in demo case
- **Explainable rules** – Eight weighted heuristics with clear explanations
- **Risk bands** – Low (0–2) · Medium (3–5) · High (6+)
- **Example Library** – Eight pre-labelled classroom scenarios
- **Rules & Scoring guide** – Full catalog and analysis flow
- **Session history** – Recent scans + CSV export
- **100% offline** – No network, no API, no trained model

---

## How to Run

Requirements: Python 3.8+ (standard library only — Tkinter is included with most Python installations).

```bash
python scam_checker_studio.py
```

> On some Linux distributions you may need to install the Tk package:
> ```bash
> sudo apt install python3-tk
> ```

---

## Project Structure

```
message-safety-desk/
├── scam_checker_studio.py   # Main application (Tkinter GUI)
├── Message_Safety_Desk.pdf  # Project presentation slides
├── README.md
├── .gitignore
└── docs/
    └── (optional screenshots / notes)
```

---

## Detection Rules (Summary)

| Rule                          | Points | What it looks for                          |
|-------------------------------|--------|--------------------------------------------|
| Secret / sign-in code request | +4     | Asking the user to share OTP / password    |
| Unusual payment method        | +3     | Gift cards, crypto, wire transfers         |
| Remote access request         | +3     | AnyDesk, TeamViewer, screen sharing        |
| Time pressure                 | +2     | “Urgent”, “immediately”, “today”           |
| Threat or consequence         | +2     | Arrest, account closure, legal action      |
| Link included                 | +1     | URL or domain pattern                      |
| Generic greeting              | +1     | “Dear customer”, “Dear user”               |
| Organization identity claim   | +1     | “This is your bank / Microsoft Support…”   |

A special safeguard treats sentences that say **“Do not share this code”** as non-requests, so legitimate OTP messages stay Low.

---

## Scoring Model

```
Score = sum of matched rule weights (each rule counts once)

Low    →  0–2
Medium →  3–5
High   →  6+
```

The score is an **explainable warning heuristic**, not a calibrated fraud probability. A High warning means “pause and verify independently”, not “this is proven fraud”.

---

## Demo Cases

All eight built-in examples produce the expected risk band:

| Example                        | Expected |
|--------------------------------|----------|
| Personal dinner plan           | Low      |
| Parcel tracking update         | Low      |
| Bank profile notice            | Medium   |
| Password reset reminder        | Medium   |
| Urgent verification code       | High     |
| Tax payment threat             | High     |
| Expected login code            | Low      |
| Remote support request         | High     |

---

## Limitations (Important)

- This is a **classroom prototype**, not production security software.
- Rules are simple heuristics; new scam language can evade them.
- Ordinary legitimate messages may also match a clue.
- The app never visits links and never proves fraud.
- Always verify through official contact channels you find yourself.

---

## Presentation

See `Message_Safety_Desk.pdf` for the full 10-slide project presentation covering:

1. Title & team
2. The human problem (authority / fear / urgency)
3. Product overview
4. System architecture
5. Detection engine (8 rules)
6. Scoring model
7. Case study – “urgent bank” trap
8. Edge-case handling (code notification vs. code request)
9. Demo results
10. Takeaway

---

## License

This project is provided for educational purposes as a class demonstration.