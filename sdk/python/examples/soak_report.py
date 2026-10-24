"""汇总 soak.py 的 CSV：总体、按小时，或者按给定的时间段（比如每次故障注入）统计。

    python soak_report.py soak.csv [soak2.csv ...]                 # 总体和每小时
    python soak_report.py -w windows.txt soak.csv [...]            # 另按时间段统计

windows.txt 每行：开始的 unix 时间、结束的 unix 时间、名字（空格分隔，名字可以带空格）。
某个时间段的统计包括在其中开始的全部循环；失败的循环列出原因。
"""
import collections
import csv
import sys
import time


def load(paths):
    rows = []
    for p in paths:
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                r["time"], r["seconds"], r["ok"] = float(r["time"]), float(r["seconds"]), r["ok"] == "1"
                rows.append(r)
    rows.sort(key=lambda r: r["time"])
    return rows


def q(xs, p):
    return xs[int(p * (len(xs) - 1))] if xs else 0.0


def line(name, rows):
    cyc = [r for r in rows if r["op"] == "cycle"]
    fails = [r for r in cyc if not r["ok"]]
    lat = sorted(r["seconds"] for r in cyc if r["ok"])
    creates = sorted(r["seconds"] for r in rows if r["op"] == "create" and r["ok"])
    rate = 100 * (1 - len(fails) / len(cyc)) if cyc else 100.0
    print(f"{name:<34} cycles {len(cyc):>7}  fail {len(fails):>4}  ok {rate:7.3f}%  "
          f"create p50 {q(creates, .5):5.2f}s p99 {q(creates, .99):5.2f}s max {q(creates, 1):6.2f}s  "
          f"cycle max {q(lat, 1):6.1f}s")
    return fails


def main(argv):
    windows = []
    if argv[:1] == ["-w"]:
        for ln in open(argv[1]):
            if ln.strip() and not ln.startswith("#"):
                a, b, name = ln.split(None, 2)
                windows.append((float(a), float(b), name.strip()))
        argv = argv[2:]
    rows = load(argv)
    if not rows:
        sys.exit("no rows")
    t0 = rows[0]["time"]
    print(f"{time.strftime('%F %T', time.localtime(t0))} .. "
          f"{time.strftime('%F %T', time.localtime(rows[-1]['time']))}")
    fails = line("total", rows)
    by_kind = collections.defaultdict(list)
    for r in rows:
        by_kind[f"  {r['kind']}/{r['backend']}"].append(r)
    for k in sorted(by_kind):
        line(k, by_kind[k])
    ops = collections.defaultdict(list)
    for r in rows:
        if r["op"] != "cycle" and r["ok"]:
            ops[r["op"]].append(r["seconds"])
    print("ops: " + "  ".join(f"{k} p50 {q(sorted(v), .5):.2f}s p99 {q(sorted(v), .99):.2f}s"
                             for k, v in sorted(ops.items())))
    if windows:
        print("\nwindows:")
        for a, b, name in windows:
            for r in line(name, [r for r in rows if a <= r["time"] < b]):
                print(f"    FAIL {time.strftime('%T', time.localtime(r['time']))} {r['kind']}/{r['backend']} {r['reason']}")
    else:
        print("\nby hour:")
        hours = collections.defaultdict(list)
        for r in rows:
            hours[int((r["time"] - t0) // 3600)].append(r)
        for h in sorted(hours):
            line(f"hour {h:>3} ({time.strftime('%m-%d %H:%M', time.localtime(t0 + h * 3600))})", hours[h])
    reasons = collections.Counter(r["reason"].split(":")[0] for r in fails)
    if reasons:
        print("\nfailure reasons:", dict(reasons))
        for r in fails[:30]:
            print(f"  {time.strftime('%F %T', time.localtime(r['time']))} {r['kind']}/{r['backend']} {r['reason']}")


main(sys.argv[1:])
