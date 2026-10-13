flowchart TD
    Step["Step uses: owner/repo@ref"] --> Filter{"Local (./) or Docker?"}
    Filter -- Yes --> Pass["Ignore"]
    Filter -- No --> Check1{"Check 1: Typo-Squat?<br/>1 <= Levenshtein(owner, trusted) <= 2"}
    
    Check1 -- Yes --> High1["HIGH: Typo-squatting detected<br/>(e.g., 'actons' spoofing 'actions')"]
    Check1 -- No --> Check2{"Check 2: Spoofed Official Repo?<br/>repo in POPULAR_ACTIONS and owner not trusted"}
    
    Check2 -- Yes --> High2["HIGH: Cloned official action<br/>(e.g., 'evil-actor/setup-python')"]
    Check2 -- No --> Check3{"Check 3: Strict allowlist mode enabled?"}
    
    Check3 -- Yes & Untrusted --> Med["MEDIUM: Unapproved third-party namespace"]
    Check3 -- No --> Clean["Pass (Clean)"]
