# Project Notes — Message Safety Desk

## Goal
Give users a transparent, offline second opinion on messages that may contain common scam patterns (urgency, credential requests, threats, remote-access tools, unusual payment methods, etc.).

## Design Principles
1. **Offline** – No network calls, no message upload.
2. **Explainable** – Every matched rule shows its name, point value and plain-language reason.
3. **Cautious language** – The app never claims “this is a scam”. It issues Low / Medium / High *warnings* and suggests verification steps.
4. **Classroom-friendly** – Built-in demo cases, rule catalog tab, and CSV export for presentation evidence.

## Architecture (5 steps)
1. **Input** – User pastes text or loads a sample.
2. **Match** – Eight case-insensitive regex rules.
3. **Score** – Sum of unique matched rule weights.
4. **Explain** – Risk band + clue table + next-step advice.
5. **Record** – In-memory history + optional CSV export.

## Special Rule Logic
For the “Secret or sign-in code request” rule the code first removes any sentence that contains “do not share” / “don’t share” / “never share”. This prevents legitimate OTP delivery messages from being flagged.

## Risk Bands
- **Low (0–2)** – Few selected clues. Does not prove the message is genuine.
- **Medium (3–5)** – Pause and verify through an official channel you find yourself.
- **High (6+)** – Do not click links, share codes, install software or send money. Contact the organization independently.

## Tech Stack
- Python 3 + Tkinter (standard library)
- `re` for pattern matching
- `csv` + `filedialog` for history export
- No external dependencies

## Presentation Flow (10 slides)
1. Title & team
2. Human problem (Authority / Fear / Urgency)
3. Product overview (single-desktop experience)
4. System architecture
5. Eight detection rules
6. Scoring model + example calculation
7. Live case study (“urgent bank” trap)
8. Edge-case handling (code notification vs request)
9. All eight demo results
10. Takeaway & Q&A 
