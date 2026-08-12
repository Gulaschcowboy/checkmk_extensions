#!/usr/bin/env bash

ARCSTATS="/proc/spl/kstat/zfs/arcstats"

if [[ ! -f "$ARCSTATS" ]]; then
    echo "2 ZFS_ARC - ARC stats not available"
    exit 0
fi

get_arc_value() {
    awk -v key="$1" '$1 == key {print $3}' "$ARCSTATS"
}

size=$(get_arc_value size)
c_max=$(get_arc_value c_max)
c_min=$(get_arc_value c_min)
hits=$(get_arc_value hits)
misses=$(get_arc_value misses)
memory_throttle_count=$(get_arc_value memory_throttle_count)

mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2 * 1024}')

# Calculations (guard against division by zero on a freshly booted/idle ARC)
arc_pct=$(awk -v size="$size" -v c_max="$c_max" 'BEGIN {printf "%.0f", (c_max > 0 ? (size/c_max)*100 : 0)}')
ram_pct=$(awk -v size="$size" -v mem_total="$mem_total" 'BEGIN {printf "%.0f", (mem_total > 0 ? (size/mem_total)*100 : 0)}')
hit_ratio=$(awk -v hits="$hits" -v misses="$misses" 'BEGIN {total=hits+misses; printf "%.1f", (total > 0 ? (hits/total)*100 : 100)}')

# Human readable
human() {
    num=$1
    awk -v num="$num" 'function human(x) {
        s="B KB MB GB TB PB"
        split(s,arr)
        for(i=1; x>=1024 && i<6; i++) x/=1024
        return sprintf("%.1f %s", x, arr[i])
    }
    BEGIN {print human(num)}'
}

size_h=$(human $size)
max_h=$(human $c_max)

# ---- STATE LOGIC ----
warn=0
crit=0
msg="OK"

if (( arc_pct > 90 )); then warn=1; fi
if (( ram_pct > 40 )); then warn=1; fi
if (( ram_pct > 60 )); then crit=1; fi

if (( $(echo "$hit_ratio < 85" | bc -l) )); then warn=1; fi
if (( $(echo "$hit_ratio < 75" | bc -l) )); then crit=1; fi

if (( memory_throttle_count > 0 )); then warn=1; fi


if (( crit == 1 )); then
    state=2; msg="CRIT"
elif (( warn == 1 )); then
    state=1; msg="WARN"
else
    state=0
fi

# ---- AUTO RECOMMENDATION ENGINE ----

recommendation="arc_ok"

# Helper: round to nearest GB
to_gb() {
    awk -v bytes="$1" 'BEGIN {printf "%.0f", bytes/1024/1024/1024}'
}

arc_max_gb=$(to_gb $c_max)
ram_total_gb=$(to_gb $mem_total)

# Case 1: ARC too large for system
if (( ram_pct > 50 )); then
    target_gb=$((ram_total_gb / 4))
    (( target_gb < 1 )) && target_gb=1
    recommendation="reduce_arc_max_to_${target_gb}G"
fi

# Case 2: Memory pressure detected
if (( memory_throttle_count > 0 )); then
    target_gb=$((ram_total_gb / 4))
    (( target_gb < 1 )) && target_gb=1
    recommendation="memory_pressure_reduce_arc_to_${target_gb}G"
fi

# Case 3: ARC too small / inefficient cache
if (( $(echo "$hit_ratio < 80" | bc -l) )) && (( ram_pct < 30 )); then
    target_gb=$((arc_max_gb + 1))
    recommendation="increase_arc_max_to_${target_gb}G"
fi

# Case 4: ARC oversized but not useful
if (( ram_pct > 35 )) && (( $(echo "$hit_ratio > 95" | bc -l) )); then
    target_gb=$((arc_max_gb - 1))
    (( target_gb < 1 )) && target_gb=1
    recommendation="oversized_arc_reduce_to_${target_gb}G"
fi

# ---- OUTPUT ----

echo "$state ZFS_ARC arc=${arc_pct}%;ram=${ram_pct}%;hit=${hit_ratio}% size=${size_h}/${max_h} hit_ratio=${hit_ratio}% ram_usage=${ram_pct}% throttle=${memory_throttle_count} rec=${recommendation}"

