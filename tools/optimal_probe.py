#!/usr/bin/env python3
"""
optimal_probe.py - Adaptive address probe planner for PS5 14.10 WebKit crash oracle.

Given a list of probed addresses and their results (HIT or MISS), computes:
1. The ruled-out VA ranges
2. The optimal next N probe addresses (logarithmic coverage)
3. P(HIT) estimates for different ASLR entropy assumptions
4. Whether blind probing is feasible or alternatives should be pursued

Usage:
    python optimal_probe.py                           # default 10 misses, next 20
    python optimal_probe.py --misses 0x200000000 0x100000000 --next 10
    python optimal_probe.py --hits 0x7F0000000000     # after a hit, plan refinement
    python optimal_probe.py --spray-mb 640 --mapped-mb 1040 --entropy-bits 24
"""

import argparse
import math
import sys

VA_MAX = 0x7FFFFFFFFFFF  # 47-bit user VA (128 TB)
VA_MIN = 0x1000          # below this is typically unmapped
PAGE_SIZE = 0x4000        # 16 KB

DEFAULT_SPRAY_MB = 640
DEFAULT_MAPPED_MB = 1040
DEFAULT_MISSES = [
    0x100000000,
    0x180000000,
    0x200000000,
    0x280000000,
    0x2F8000000,
]

def parse_hex_list(s):
    return [int(x, 16) if x.startswith('0x') else int(x) for x in s]

def align_down(addr):
    return addr & ~(PAGE_SIZE - 1)

def align_up(addr):
    return (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

def mb_to_bytes(mb):
    return int(mb * 1024 * 1024)

def bytes_to_human(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def compute_ruled_out(misses, mapped_bytes):
    """Each miss at addr X rules out that any mapped page overlaps X.
    With mapped_bytes contiguous, miss at X rules out base in [X - mapped_bytes, X]."""
    intervals = []
    for addr in misses:
        lo = max(VA_MIN, addr - mapped_bytes)
        hi = min(VA_MAX, addr + mapped_bytes)
        intervals.append((lo, hi))

    intervals.sort()
    merged = [intervals[0]]
    for lo, hi in intervals[1:]:
        if lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))

    total = sum(hi - lo for lo, hi in merged)
    return merged, total

def p_hit_per_probe(mapped_bytes, aslr_window_bytes):
    if aslr_window_bytes <= mapped_bytes:
        return 1.0
    return mapped_bytes / aslr_window_bytes

def expected_probes(p_hit):
    if p_hit <= 0:
        return float('inf')
    return 1.0 / p_hit

def p_all_miss(p_hit, n_probes):
    return (1.0 - p_hit) ** n_probes

def generate_log_probes(n, ruled_out_intervals, hits=None):
    """Generate n probe addresses with logarithmic coverage of the remaining VA space."""
    def is_ruled_out(addr):
        for lo, hi in ruled_out_intervals:
            if lo <= addr <= hi:
                return True
        return False

    candidates = []

    # generate candidates at power-of-2 boundaries and logarithmic midpoints
    # across the full 47-bit VA space
    powers = []
    val = 0x400000000  # start at 16 GB (above typical ruled-out zone)
    while val <= VA_MAX:
        powers.append(val)
        val *= 2

    # add midpoints between consecutive powers
    midpoints = []
    for i in range(len(powers) - 1):
        mid = (powers[i] + powers[i + 1]) // 2
        midpoints.append(align_down(mid))

    # add the Linux-style mmap region explicitly
    high_priority = [
        0x7F0000000000,   # Linux-style mmap top
        0x000800000000,   # 32 GB - just above typical ruled-out zone
        0x000400000000,   # 16 GB
    ]

    all_candidates = high_priority + powers + midpoints
    all_candidates = [align_down(a) for a in all_candidates]

    # remove ruled-out and duplicates
    seen = set()
    filtered = []
    for addr in all_candidates:
        if addr in seen or is_ruled_out(addr) or addr < VA_MIN or addr > VA_MAX:
            continue
        seen.add(addr)
        filtered.append(addr)

    # if we have hits, prioritize addresses near them (binary search refinement)
    if hits:
        near_hit = []
        for h in hits:
            for delta in [0x40000000, -0x40000000, 0x10000000, -0x10000000,
                          0x4000000, -0x4000000, 0x1000000, -0x1000000]:
                addr = align_down(h + delta)
                if VA_MIN <= addr <= VA_MAX and not is_ruled_out(addr) and addr not in seen:
                    near_hit.append(addr)
                    seen.add(addr)
        filtered = near_hit + filtered

    return filtered[:n]

def print_feasibility(mapped_mb, spray_mb):
    mapped_bytes = mb_to_bytes(mapped_mb)
    print("\n--- ASLR Feasibility Analysis ---")
    print(f"Mapped memory: {mapped_mb} MB ({bytes_to_human(mapped_bytes)})")
    print(f"Spray: {spray_mb} MB")
    print(f"VA space: {bytes_to_human(VA_MAX)}")
    print()
    print(f"{'Entropy':>8} | {'Window':>10} | {'P(HIT)':>10} | {'E[probes]':>10} | {'Wall time':>12} | Feasible?")
    print("-" * 80)

    for bits in [0, 12, 16, 20, 24, 28, 32, 36, 47]:
        window = PAGE_SIZE * (2 ** bits) if bits > 0 else mapped_bytes
        p = p_hit_per_probe(mapped_bytes, window)
        ep = expected_probes(p)
        seconds = ep * 30  # ~30s per probe including spray time
        if seconds < 60:
            time_str = f"{seconds:.0f}s"
        elif seconds < 3600:
            time_str = f"{seconds / 60:.1f} min"
        elif seconds < 86400:
            time_str = f"{seconds / 3600:.1f} hr"
        else:
            time_str = f"{seconds / 86400:.1f} days"

        feasible = "YES" if ep < 100 else ("MARGINAL" if ep < 1000 else "NO")
        label = "deterministic" if bits == 0 else f"{bits} bits"
        print(f"{label:>8} | {bytes_to_human(window):>10} | {p:>10.6f} | {ep:>10.0f} | {time_str:>12} | {feasible}")

def main():
    parser = argparse.ArgumentParser(description="PS5 14.10 WebKit crash oracle probe planner")
    parser.add_argument('--misses', nargs='*', default=None,
                        help='Hex addresses that MISSed (e.g., 0x200000000)')
    parser.add_argument('--hits', nargs='*', default=None,
                        help='Hex addresses that HIT')
    parser.add_argument('--next', type=int, default=20,
                        help='Number of next probe addresses to generate')
    parser.add_argument('--spray-mb', type=float, default=DEFAULT_SPRAY_MB,
                        help='Spray size in MB (default: 640)')
    parser.add_argument('--mapped-mb', type=float, default=DEFAULT_MAPPED_MB,
                        help='Total mapped memory in MB (default: 1040)')
    parser.add_argument('--entropy-bits', type=int, default=None,
                        help='Assumed ASLR entropy in bits (for P(HIT) calculation)')
    args = parser.parse_args()

    misses = parse_hex_list(args.misses) if args.misses else DEFAULT_MISSES
    hits = parse_hex_list(args.hits) if args.hits else []
    mapped_bytes = mb_to_bytes(args.mapped_mb)
    spray_bytes = mb_to_bytes(args.spray_mb)

    print("=" * 70)
    print("PS5 14.10 WebKit Crash Oracle - Optimal Probe Planner")
    print("=" * 70)

    # ruled-out analysis
    if misses:
        ruled_out, total_ruled = compute_ruled_out(misses, mapped_bytes)
        print(f"\n--- Ruled-Out Ranges ({len(misses)} misses, {bytes_to_human(mapped_bytes)} footprint) ---")
        for lo, hi in ruled_out:
            print(f"  0x{lo:012X} - 0x{hi:012X}  ({bytes_to_human(hi - lo)})")
        print(f"  Total ruled out: {bytes_to_human(total_ruled)}")
        print(f"  Remaining VA: {bytes_to_human(VA_MAX - total_ruled)}")
    else:
        ruled_out = []

    # hits analysis
    if hits:
        print(f"\n--- HIT Analysis ---")
        for h in hits:
            print(f"  HIT at 0x{h:012X} — spray is in this region")
            print(f"  → Binary search: probe ±1GB from hit to find boundaries")
            print(f"  → Chain 500 reads from this page to map heap structure")

    # feasibility
    print_feasibility(args.mapped_mb, args.spray_mb)

    # consistency check
    if misses and args.entropy_bits is not None:
        window = PAGE_SIZE * (2 ** args.entropy_bits)
        p = p_hit_per_probe(mapped_bytes, window)
        p_miss_all = p_all_miss(p, len(misses))
        print(f"\n--- Consistency Check ---")
        print(f"At {args.entropy_bits} bits entropy: P(all {len(misses)} miss) = {p_miss_all:.4f}")
        if p_miss_all < 0.01:
            print("  ⚠ INCONSISTENT: this many misses is very unlikely at this entropy")
        elif p_miss_all < 0.1:
            print("  ⚠ Unlikely but possible")
        else:
            print("  ✓ Consistent with observed data")

    # generate next probes
    print(f"\n--- Next {args.next} Optimal Probe Addresses ---")
    probes = generate_log_probes(args.next, ruled_out, hits)
    for i, addr in enumerate(probes, 1):
        print(f"  {i:>2}. 0x{addr:012X}  ({bytes_to_human(addr)})")

    # recommendation
    print(f"\n--- Recommendation ---")
    if hits:
        print("  You have a HIT. Switch to binary search refinement around the hit.")
        print("  Use the 500 chained reads to map the heap, find ArrayBuffer headers,")
        print("  locate JSCell vtables, and derive the ASLR slide.")
    elif len(misses) >= 10:
        print("  10+ misses in [4GB, 12.8GB]. The heap is NOT in this range.")
        print("  Priority: probe the upper VA range (0x7F0000000000) and power-of-2 boundaries.")
        print("  ")
        print("  ALTERNATIVE: If CVE-2026-64784 (MetadataTable overflow) is confirmed,")
        print("  use heap feng shui to leak pointers WITHOUT crashing. This is faster")
        print("  and more reliable than blind address probing.")
    else:
        print("  Continue probing with logarithmic coverage.")

    print()

if __name__ == '__main__':
    main()
