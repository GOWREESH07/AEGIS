#!/usr/bin/env python3
"""
aggregate.py — Metrics aggregator for AEGIS trial results

Reads a results CSV from run_trials.py and produces:
  - Per-stage latency table (mean/std)
  - Attack success rate with/without AEGIS
  - False-positive rate
  - Self-healing latency delta

Usage:
    python analysis/aggregate.py --input results.csv [--charts]

Requirements:
    pip install pandas matplotlib tabulate
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    return df


def print_separator(width: int = 70) -> None:
    print("─" * width)


def aggregate(df: pd.DataFrame, args: argparse.Namespace) -> None:
    print()
    print_separator()
    print("  AEGIS SIMULATION RESULTS")
    print_separator()

    # ── Attack Success Rate ───────────────────────────────────────────────
    off_df = df[df["mode"] == "aegis_off"].drop_duplicates("trial_id")
    on_df = df[df["mode"] == "aegis_on"].drop_duplicates("trial_id")

    baseline_success = off_df["attack_succeeded"].mean() if len(off_df) > 0 else float("nan")
    defended_success = on_df["attack_succeeded"].mean() if len(on_df) > 0 else float("nan")

    print(f"\n  Attack Success Rate")
    print(f"  {'Baseline (AEGIS off)':<30s} {baseline_success:.0%}")
    print(f"  {'Defended (AEGIS on)':<30s} {defended_success:.0%}")

    # ── False Positive Rate ───────────────────────────────────────────────
    fp_rate = on_df["fp_rate"].mean() if len(on_df) > 0 else float("nan")
    print(f"\n  False-Positive Rate (benign traffic): {fp_rate:.2%}")

    # ── Per-Stage Detection Latency ───────────────────────────────────────
    print(f"\n  Per-Stage Detection Latency (AEGIS enabled)")
    print_separator()
    print(f"  {'STAGE':<10} {'MEAN (ms)':>12} {'STD (ms)':>12} {'N TRIALS':>10}")
    print_separator()

    aegis_on = df[df["mode"] == "aegis_on"]
    for stage in range(1, 6):
        stage_df = aegis_on[aegis_on["stage"] == stage]["detection_latency_ms"]
        if len(stage_df) == 0:
            print(f"  Stage {stage:<5}  {'N/A':>12} {'N/A':>12} {'0':>10}")
        else:
            print(
                f"  Stage {stage:<5}  {stage_df.mean():>12.1f} {stage_df.std():>12.1f} {len(stage_df):>10}"
            )
    print_separator()

    # ── Self-Healing Delta ────────────────────────────────────────────────
    healing_delta = aegis_on["healing_delta_ms"].mean() if len(aegis_on) > 0 else 0.0
    print(f"\n  Self-Healing Latency Delta: {healing_delta:+.0f} ms")
    print(f"  (negative = second run detected faster)")

    # ── End-to-End Latency ────────────────────────────────────────────────
    e2e_off = off_df["detection_latency_ms"].mean() if len(off_df) > 0 else float("nan")
    e2e_on = aegis_on.groupby("trial_id")["detection_latency_ms"].sum().mean()
    print(f"\n  End-to-End Pipeline Latency")
    print(f"  {'Baseline (unprotected)':<30s} {e2e_off:.0f} ms")
    print(f"  {'Defended (AEGIS blocked)':<30s} {e2e_on:.0f} ms")
    print_separator()

    # ── Charts ────────────────────────────────────────────────────────────
    if args.charts:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            fig, axes = plt.subplots(1, 2, figsize=(14, 5))
            fig.patch.set_facecolor("#0d0d0d")

            # Chart 1: Per-stage latency
            ax = axes[0]
            ax.set_facecolor("#111111")
            stages = range(1, 6)
            means = []
            stds = []
            for s in stages:
                sdf = aegis_on[aegis_on["stage"] == s]["detection_latency_ms"]
                means.append(sdf.mean() if len(sdf) > 0 else 0)
                stds.append(sdf.std() if len(sdf) > 0 else 0)

            ax.bar(stages, means, yerr=stds, color="#f5a623", alpha=0.85, capsize=4, width=0.5)
            ax.set_xlabel("Stage", color="#888888", fontsize=10)
            ax.set_ylabel("Detection Latency (ms)", color="#888888", fontsize=10)
            ax.set_title("Per-Stage Detection Latency (AEGIS On)", color="#c9c9c9", fontsize=11)
            ax.tick_params(colors="#888888")
            ax.spines["bottom"].set_color("#2a2a2a")
            ax.spines["left"].set_color("#2a2a2a")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.set_xticks(list(stages))
            ax.set_xticklabels(["Recon", "Adapt", "AILM", "Lateral", "Exec"], color="#888888")

            # Chart 2: Attack success rate comparison
            ax2 = axes[1]
            ax2.set_facecolor("#111111")
            categories = ["Baseline\n(AEGIS off)", "Defended\n(AEGIS on)"]
            values = [baseline_success * 100, defended_success * 100]
            colors = ["#ef4444", "#22c55e"]
            bars = ax2.bar(categories, values, color=colors, alpha=0.85, width=0.4)
            ax2.set_ylabel("Attack Success Rate (%)", color="#888888", fontsize=10)
            ax2.set_title("Attack Success Rate Comparison", color="#c9c9c9", fontsize=11)
            ax2.set_ylim(0, 110)
            ax2.tick_params(colors="#888888")
            ax2.spines["bottom"].set_color("#2a2a2a")
            ax2.spines["left"].set_color("#2a2a2a")
            ax2.spines["top"].set_visible(False)
            ax2.spines["right"].set_visible(False)
            for bar, val in zip(bars, values):
                ax2.text(
                    bar.get_x() + bar.get_width() / 2,
                    val + 2,
                    f"{val:.0f}%",
                    ha="center",
                    va="bottom",
                    color="#c9c9c9",
                    fontsize=11,
                    fontweight="bold",
                )

            plt.tight_layout()
            chart_path = Path(args.input).parent / "aegis_results.png"
            plt.savefig(chart_path, dpi=150, bbox_inches="tight", facecolor="#0d0d0d")
            print(f"\n  Charts saved to: {chart_path}")
        except ImportError:
            print("\n  [charts] matplotlib not installed. Run: pip install matplotlib")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS results aggregator")
    parser.add_argument("--input", type=str, default="results.csv", help="Path to results CSV")
    parser.add_argument("--charts", action="store_true", help="Generate matplotlib charts")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"ERROR: {args.input} not found. Run scripts/run_trials.py first.")
        return

    df = load(args.input)
    aggregate(df, args)


if __name__ == "__main__":
    main()
