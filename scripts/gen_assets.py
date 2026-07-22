"""Generate neon cyber visuals for the OmniShield deck -> assets/*.png

Run:  venv\\Scripts\\python scripts\\gen_assets.py
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Circle, Wedge

ASSETS = os.path.join(os.path.dirname(__file__), "..", "assets")
os.makedirs(ASSETS, exist_ok=True)

BG = "#0A0F1E"
CARD = "#0D1424"
WHITE = "#F1F5F9"
MUTED = "#94A3B8"
BLUE = "#3B82F6"
EMER = "#10B981"
AMBER = "#F59E0B"
RED = "#EF4444"
PURPLE = "#A78BFA"


def save(fig, name, transparent=False):
    fig.savefig(os.path.join(ASSETS, name), dpi=200, facecolor=fig.get_facecolor(),
                transparent=transparent, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


# ---------- hero network background (16:9) ---------------------------------
def hero():
    rng = np.random.default_rng(7)
    n = 120
    pts = rng.random((n, 2)) * np.array([16, 9])
    fig, ax = plt.subplots(figsize=(16, 9), facecolor=BG)
    ax.set_facecolor(BG); ax.set_xlim(0, 16); ax.set_ylim(0, 9); ax.axis("off")
    # edges between nearby nodes (dimmer on the left to keep text readable)
    for i in range(n):
        for j in range(i + 1, n):
            d = np.hypot(*(pts[i] - pts[j]))
            if d < 1.7:
                x = (pts[i, 0] + pts[j, 0]) / 2
                a = (0.04 + 0.10 * (x / 16)) * (1 - d / 1.7)
                ax.plot([pts[i, 0], pts[j, 0]], [pts[i, 1], pts[j, 1]],
                        color=BLUE, lw=0.8, alpha=a, zorder=1)
    cols = rng.choice([BLUE, EMER, PURPLE, BLUE, BLUE], n)
    for (x, y), c in zip(pts, cols):
        a = 0.25 + 0.65 * (x / 16)
        for r, al in [(180, 0.05 * a), (90, 0.10 * a), (28, a)]:
            ax.scatter(x, y, s=r, color=c, alpha=al, edgecolors="none", zorder=2)
    save(fig, "hero_bg.png")


# ---------- detection benchmark bars ---------------------------------------
def detection():
    fig, ax = plt.subplots(figsize=(6.4, 4.6), facecolor=CARD)
    ax.set_facecolor(CARD)
    labels = ["z-score\n(univariate)", "IsolationForest\n(ours)", "One-Class SVM"]
    vals = [0.15, 0.93, 0.94]
    cols = [RED, EMER, BLUE]
    bars = ax.bar(labels, vals, color=cols, width=0.6, zorder=3)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}",
                ha="center", color=WHITE, fontsize=17, fontweight="bold")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Detection F1", color=MUTED, fontsize=12)
    ax.tick_params(colors=MUTED, labelsize=11)
    for sp in ax.spines.values():
        sp.set_color("#22304A")
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, color="#1B263B", lw=0.8)
    ax.set_axisbelow(True)
    save(fig, "detection_chart.png")


# ---------- attribution RAG vs zero-shot -----------------------------------
def attribution():
    fig, ax = plt.subplots(figsize=(6.4, 4.6), facecolor=CARD)
    ax.set_facecolor(CARD)
    labels = ["Zero-shot LLM", "RAG (ours)"]
    vals = [0.35, 0.75]
    cols = [MUTED, PURPLE]
    bars = ax.bar(labels, vals, color=cols, width=0.55, zorder=3)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.2f}",
                ha="center", color=WHITE, fontsize=18, fontweight="bold")
    ax.annotate("", xy=(1, 0.75), xytext=(0, 0.35),
                arrowprops=dict(arrowstyle="-|>", color=EMER, lw=2.5))
    ax.text(0.5, 0.60, "+2×", color=EMER, fontsize=16, fontweight="bold", ha="center")
    ax.set_ylim(0, 0.9)
    ax.set_ylabel("Top-1 accuracy", color=MUTED, fontsize=12)
    ax.tick_params(colors=MUTED, labelsize=12)
    ax.spines[["top", "right"]].set_visible(False)
    for sp in ax.spines.values():
        sp.set_color("#22304A")
    ax.yaxis.grid(True, color="#1B263B", lw=0.8); ax.set_axisbelow(True)
    save(fig, "attribution_chart.png")


# ---------- kill-chain graph (wide) ----------------------------------------
def killchain():
    stages = ["Recon", "Initial\nAccess", "Execution", "Discovery",
              "Lateral\nMovement", "Collection", "Exfil", "Impact"]
    cur, nxt = 3, 4  # Discovery -> Lateral Movement
    fig, ax = plt.subplots(figsize=(16, 4.2), facecolor=BG)
    ax.set_facecolor(BG); ax.axis("off")
    ax.set_xlim(-0.6, len(stages) - 0.4); ax.set_ylim(-1.4, 1.4)
    xs = range(len(stages))
    for i in range(len(stages) - 1):
        ax.annotate("", xy=(i + 0.72, 0), xytext=(i + 0.28, 0),
                    arrowprops=dict(arrowstyle="-|>", color="#2A3A57", lw=2))
    for i, s in zip(xs, stages):
        if i == cur:
            c, ring, lbl = EMER, EMER, "YOU ARE HERE"
        elif i == nxt:
            c, ring, lbl = AMBER, AMBER, "PREDICTED NEXT"
        elif i == len(stages) - 1:
            c, ring, lbl = RED, "#3A1620", ""
        else:
            c, ring, lbl = "#1C2740", "#243250", ""
        for r, al in [(0.42, 0.18), (0.30, 0.35), (0.20, 1.0)]:
            ax.add_patch(Circle((i, 0), r, color=c, alpha=al, zorder=3))
        ax.add_patch(Circle((i, 0), 0.20, fill=False, ec=ring, lw=2, zorder=4))
        ax.text(i, -0.62, s, ha="center", va="top", color=WHITE, fontsize=12,
                fontweight="bold" if i in (cur, nxt) else "normal")
        if lbl:
            ax.text(i, 0.62, lbl, ha="center", color=c, fontsize=10.5, fontweight="bold")
    save(fig, "killchain.png")


# ---------- closed-loop ring -----------------------------------------------
def loop():
    steps = [("DETECT", BLUE), ("ATTRIBUTE", PURPLE), ("PREDICT", AMBER),
             ("CORRELATE", EMER), ("CONTAIN", RED), ("AUDIT", MUTED)]
    fig, ax = plt.subplots(figsize=(7.5, 7.5), facecolor=BG)
    ax.set_facecolor(BG); ax.axis("off")
    ax.set_xlim(-1.5, 1.5); ax.set_ylim(-1.5, 1.5); ax.set_aspect("equal")
    R = 1.05
    ang = np.linspace(90, 90 - 360, len(steps) + 1)[:-1] * np.pi / 180
    pos = [(R * np.cos(a), R * np.sin(a)) for a in ang]
    for i in range(len(steps)):
        x0, y0 = pos[i]; x1, y1 = pos[(i + 1) % len(steps)]
        ax.add_patch(FancyArrowPatch((x0 * 1.0, y0 * 1.0), (x1 * 1.0, y1 * 1.0),
                     connectionstyle="arc3,rad=-0.28", arrowstyle="-|>",
                     mutation_scale=18, color="#2A3A57", lw=2, zorder=1))
    for (x, y), (name, c) in zip(pos, steps):
        for r, al in [(0.44, 0.14), (0.33, 0.28), (0.24, 1.0)]:
            ax.add_patch(Circle((x, y), r, color=c, alpha=al, zorder=3))
        ax.text(x, y, name, ha="center", va="center", color="#0A0F1E",
                fontsize=11, fontweight="bold", zorder=4)
    ax.text(0, 0.12, "OmniShield", ha="center", color=WHITE, fontsize=17, fontweight="bold")
    ax.text(0, -0.16, "closed loop", ha="center", color=MUTED, fontsize=11)
    save(fig, "loop.png", transparent=True)


# ---------- accuracy gauge --------------------------------------------------
def gauge(pct=94):
    fig, ax = plt.subplots(figsize=(6.0, 3.7), facecolor=CARD)
    ax.set_facecolor(CARD); ax.axis("off")
    ax.set_xlim(-1.25, 1.25); ax.set_ylim(-0.25, 1.25); ax.set_aspect("equal")
    ax.add_patch(Wedge((0, 0), 1.0, 0, 180, width=0.26, facecolor="#1B263B"))
    ang = 180 - (pct / 100) * 180
    ax.add_patch(Wedge((0, 0), 1.0, ang, 180, width=0.26, facecolor=EMER))
    ax.text(0, 0.28, f"{pct}%", ha="center", color=WHITE, fontsize=34, fontweight="bold")
    ax.text(0, 0.02, "live detection accuracy", ha="center", color=MUTED, fontsize=12)
    save(fig, "gauge.png")


hero(); detection(); attribution(); killchain(); loop(); gauge()
print("assets written to", os.path.abspath(ASSETS))
print(os.listdir(ASSETS))
