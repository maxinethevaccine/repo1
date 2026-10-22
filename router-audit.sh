#!/bin/sh
# router-audit.sh - READ-ONLY audit for a Technicolor / Telstra Smart Modem (BusyBox ash).
#
# It changes nothing on the router. It only creates two tiny temp files in /tmp
# (RAM) and deletes them when it finishes.
#
# Run it from your Mac without copying anything onto the router:
#   ssh root@192.168.0.1 'sh -s' < router-audit.sh | tee audit-report.txt
#
# (This dropbear has no scp helper, so plain "scp" will fail. If you want the
#  file on the router anyway:  ssh root@192.168.0.1 'cat > /tmp/audit.sh' < router-audit.sh )
#
# Optional settings, placed before "sh -s":
#   REF="2026-10-07 18:10:00"    time of the flash/reset; files changed after it are listed
#   EXTRA_IPS="1.2.3.4 5.6.7.8"  extra addresses to look for in firewall rules and conntrack
#   e.g.  ssh root@192.168.0.1 'REF="2026-10-07 18:10:00" sh -s' < router-audit.sh
#
# Output lines:  OK = as expected   INFO = for you to read   WARN = look at it   FAIL = real problem

REF="${REF:-2026-10-07 18:10:00}"
BAD_IPS="91.239.211.89 194.5.97.185 ${EXTRA_IPS:-}"
REFF="/tmp/.audit_ref.$$"
CNT="/tmp/.audit_cnt.$$"
: > "$CNT"
touch -d "$REF" "$REFF" 2>/dev/null || { echo "WARN  could not parse REF='$REF'; overlay-change list will be empty"; touch "$REFF"; }

hdr()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf 'OK    %s\n' "$*"; }
info() { printf 'INFO  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; printf 'W' >> "$CNT"; }
bad()  { printf 'FAIL  %s\n' "$*"; printf 'F' >> "$CNT"; }
ind()  { sed 's/^/        /'; }

hdr "0. System"
info "date:   $(date)"
info "uptime: $(uptime)"
WAN=$(ip route 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -n "$WAN" ] || WAN=eth4
WANIP=$(ip -4 addr show "$WAN" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')
info "WAN interface: $WAN   WAN IP: ${WANIP:-unknown}   reference time: $REF"

# ---------------------------------------------------------------- 1
hdr "1. Leftovers of the malware seen in this incident"
HITS=$(find /tmp /var /root /overlay /etc /usr/bin /usr/sbin /opt \( -name astats -o -name kstats -o -name netai -o -name .redtail -o -name w.sh \) 2>/dev/null | head -n 10)
if [ -n "$HITS" ]; then bad "files with names used by the malware:"; echo "$HITS" | ind; else ok "no files named astats / kstats / netai / .redtail / w.sh"; fi
PROCS=$(ps w 2>/dev/null | grep -E 'astats|kstats|netai|redtail|w\.sh' | grep -vE 'grep|sh -s|router-audit')
if [ -n "$PROCS" ]; then bad "processes with malware names:"; echo "$PROCS" | ind; else ok "no processes with those names"; fi
N=$(ls -A /tmp/shm 2>/dev/null | wc -l)
if [ "$N" -eq 0 ]; then ok "/tmp/shm (= /dev/shm) is empty"; else warn "/tmp/shm has $N entries:"; ls -la /tmp/shm | ind; fi

# ---------------------------------------------------------------- 2
hdr "2. Cron jobs"
for f in /etc/crontabs/* /overlay/bank_*/etc/crontabs/*; do
  [ -f "$f" ] || continue
  info "$f"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) ;;
      "3 3 12 12 * /usr/bin/nginx-util 'add_ssl' '_lan'"|"*/2 * * * * /sbin/trafficmon.lua") ok "stock entry: $line" ;;
      *) warn "unexpected cron line: $line" ;;
    esac
  done < "$f"
done

# ---------------------------------------------------------------- 3
hdr "3. Boot hook (rc.local) versus the stock image"
if [ -f /rom/etc/rc.local ] && [ -f /etc/rc.local ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    if ! grep -Fxq -- "$line" /rom/etc/rc.local; then
      warn "rc.local line that is not in the stock file: $line"
      case "$line" in
        /*)
          prog=${line%% *}; b=${prog##*/}
          if [ ! -e "$prog" ]; then
            warn "  program does not exist: $prog"
          elif [ -n "$(find /overlay -name "$b" 2>/dev/null | head -n 1)" ]; then
            bad "  $prog is also present in the OVERLAY (written after the flash)"
          else
            info "  $prog lives in the read-only base image, so it was not added after the flash"
          fi ;;
      esac
    fi
  done < /etc/rc.local
else
  info "cannot compare rc.local (no copy in /rom)"
fi
info "boot scripts changed in the overlay since $REF:"
for b in /overlay/bank_*; do
  [ -d "$b" ] || continue
  find "$b/etc/init.d" "$b/etc/rc.d" -type f -newer "$REFF" 2>/dev/null
done | ind

# ---------------------------------------------------------------- 4
hdr "4. Files written to the overlay since $REF"
for b in /overlay/bank_*; do
  [ -d "$b" ] || continue
  info "$b"
  find "$b" -type f -newer "$REFF" 2>/dev/null \
    | grep -vE '/(cgroups|lxc|airties-edge|log|lot|dumaos)/|\.db(-wal|-shm)?$|\.log(\.[0-9])?$|first_boot_done|/etc/\.cfg$' \
    | while read -r f; do
        case "$f" in
          */usr/*|*/bin/*|*/sbin/*|*/lib/*|*/www/*|*/etc/init.d/*|*/etc/rc.*|*/etc/ld.so*|*/etc/profile*|*/etc/passwd*|*/etc/sysctl*|*/etc/crontabs/*)
            warn "changed since the flash (review): $f" ;;
          *) info "changed: $f" ;;
        esac
      done
done

# ---------------------------------------------------------------- 5
hdr "5. Core programs versus the stock image (/rom)"
for p in /usr/sbin/dropbear /bin/busybox /usr/sbin/nginx /sbin/procd /sbin/ubusd /usr/sbin/odhcpd /usr/sbin/dnsmasq /usr/sbin/ntpd; do
  [ -f "$p" ] || continue
  if [ -f "/rom$p" ]; then
    a=$(md5sum "$p" | cut -c1-32); s=$(md5sum "/rom$p" | cut -c1-32)
    if [ "$a" = "$s" ]; then ok "identical to stock: $p"; else warn "DIFFERS from stock: $p"; fi
  else
    info "not present in /rom, cannot compare: $p"
  fi
done
LIVE=$(md5sum /usr/sbin/dropbear 2>/dev/null | cut -c1-32)
ORIG=$(md5sum /root/dropbear.orig 2>/dev/null | cut -c1-32)
STOCK=$(md5sum /rom/usr/sbin/dropbear 2>/dev/null | cut -c1-32)
info "dropbear md5   live=$LIVE   /root/dropbear.orig=${ORIG:-n/a}   stock=${STOCK:-n/a}"
if [ -n "$STOCK" ] && [ "$LIVE" = "$STOCK" ]; then
  ok "live dropbear is the stock binary"
elif [ -n "$STOCK" ] && [ -n "$ORIG" ] && [ "$ORIG" = "$STOCK" ]; then
  warn "live dropbear is NOT stock; /root/dropbear.orig IS stock. Fine only if you installed the modified build yourself"
elif [ -n "$STOCK" ]; then
  warn "live dropbear is not stock and dropbear.orig is not stock either"
fi

# ---------------------------------------------------------------- 6
hdr "6. Accounts and SSH keys"
for u in $(awk -F: '$3==0 {print $1}' /etc/passwd); do
  case "$u" in
    root) ok "UID-0 account: root" ;;
    tchroot) warn "UID-0 account 'tchroot' (not in the stock /rom/etc/passwd)" ;;
    *) bad "unexpected UID-0 account: $u" ;;
  esac
done
if [ -f /rom/etc/passwd ]; then
  for u in $(cut -d: -f1 /etc/passwd); do
    grep -q "^$u:" /rom/etc/passwd || info "account not in the stock image: $u"
  done
fi
PW=""; EMPTYPW=""
for n in $(cut -d: -f1 /etc/shadow 2>/dev/null); do
  h=$(grep "^$n:" /etc/shadow | cut -d: -f2)
  if [ -z "$h" ]; then EMPTYPW="$EMPTYPW $n"
  else case "$h" in '*'*|'!'*) ;; *) PW="$PW $n" ;; esac
  fi
done
info "accounts with a password hash:${PW:- none}"
if [ -n "$EMPTYPW" ]; then bad "accounts with an EMPTY password:$EMPTYPW"; else ok "no account has an empty password"; fi
K=$(find /etc /root /home /overlay -name authorized_keys -size +0c 2>/dev/null)
if [ -n "$K" ]; then warn "non-empty authorized_keys files:"; echo "$K" | ind; else ok "no non-empty authorized_keys files"; fi
REFS=$(find /etc /usr/bin /usr/sbin /usr/lib/lua /lib -type f -size -2000k 2>/dev/null | xargs grep -l tchroot 2>/dev/null | head -n 5)
if [ -n "$REFS" ]; then
  info "firmware files that mention 'tchroot' (suggests a vendor account):"; echo "$REFS" | ind
else
  warn "nothing on the router mentions 'tchroot'"
fi

# ---------------------------------------------------------------- 7
hdr "7. Network"
for ip in $BAD_IPS; do
  if iptables -S 2>/dev/null | grep -q -- "-d $ip"; then
    ok "firewall rule present for $ip"
  else
    warn "no firewall rule for $ip (a reboot or firewall reload removes manual rules)"
  fi
  for ch in FORWARD OUTPUT; do
    pk=$(iptables -nvL "$ch" -x 2>/dev/null | awk -v ip="$ip" '$9==ip {print $1; exit}')
    if [ -n "$pk" ] && [ "$pk" -gt 0 ]; then warn "  $pk packets dropped in $ch toward $ip: something is still trying to reach it"; fi
  done
  CT=$(grep "dst=$ip " /proc/net/nf_conntrack 2>/dev/null)
  if [ -n "$CT" ]; then
    warn "conntrack flows toward $ip from these hosts:"
    echo "$CT" | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}' | sort | uniq -c | ind
  fi
done
for t in iptables ip6tables; do
  R=$($t -S zone_wan_input 2>/dev/null | grep ACCEPT | grep -E -- '--dport (22|23|80|88|139|443|445|5000|9443)( |$)')
  if [ -n "$R" ]; then warn "$t: WAN input accepts a management/SMB/UPnP port:"; echo "$R" | ind
  else ok "$t: WAN input accepts none of the management, SMB or UPnP ports"; fi
done
info "WAN input rules (iptables):"; iptables -S zone_wan_input 2>/dev/null | ind
info "WAN input rules (ip6tables):"; ip6tables -S zone_wan_input 2>/dev/null | ind
EST=$(netstat -tn 2>/dev/null | grep ESTABLISHED | grep -vE '127\.0\.0\.1|192\.168\.|::1|fe80')
if [ -n "$EST" ]; then info "established TCP connections to non-LAN hosts:"; echo "$EST" | ind; else ok "no established TCP connections to non-LAN hosts"; fi
if [ -n "$WANIP" ]; then
  FLOWS=$(grep "src=$WANIP " /proc/net/nf_conntrack 2>/dev/null)
  SYN=$(echo "$FLOWS" | grep -c SYN_SENT)
  S22=$(echo "$FLOWS" | grep -c 'dport=22 ')
  info "router-originated flows: SYN_SENT=$SYN   to port 22=$S22"
  if [ "$SYN" -gt 50 ] || [ "$S22" -gt 10 ]; then warn "many outbound connection attempts from the router itself (scanner-like)"; else ok "no scanner-like outbound pattern from the router"; fi
fi
sample() { sed 's/^ *//; s/:/ /' /proc/net/dev | awk -v i="$WAN" '$1==i {print $2, $10}'; }
A=$(sample); sleep 10; B=$(sample)
if [ -n "$A" ] && [ -n "$B" ]; then
  RATES=$(echo "$A $B" | awk '{printf "%d %d", ($3-$1)/10, ($4-$2)/10}')
  RX=${RATES% *}; TX=${RATES#* }
  info "$WAN over 10 s: receiving ${RX} B/s, sending ${TX} B/s"
  if [ "$RX" -gt 500000 ] || [ "$TX" -gt 500000 ]; then warn "high WAN traffic right now; is the VPN in use? If not, find the source"; else ok "WAN traffic is low"; fi
  set -- $B
  info "$WAN totals since boot: received $(( $1 / 1048576 )) MiB, sent $(( $2 / 1048576 )) MiB"
fi

# ---------------------------------------------------------------- 8
hdr "8. Processes and load"
top -b -n 1 2>/dev/null | head -n 10 | ind
IDLE=$(top -b -n 1 2>/dev/null | awk '/^CPU:/ {for(i=1;i<=NF;i++) if($i=="idle"){v=$(i-1); sub(/%/,"",v); print v}}')
if [ -n "$IDLE" ] && [ "$IDLE" -lt 70 ]; then warn "CPU is only ${IDLE}% idle (normal here is about 90%)"; else ok "CPU idle ${IDLE:-?}%"; fi
ODD=$(for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null); [ -n "$e" ] && echo "${p#/proc/} $e"; done | grep -vE ' /(usr|bin|sbin|lib|airties-edge)/')
if [ -n "$ODD" ]; then warn "processes running from unusual locations:"; echo "$ODD" | ind; else ok "every running program is in a system directory"; fi

# ---------------------------------------------------------------- 9
hdr "9. Specific items from the investigation"
SYSLIVE=$(grep -v '^#' /etc/sysctl.conf 2>/dev/null | grep -v '^$' | tr '\n' ';')
SYSROM=""
[ -f /rom/etc/sysctl.conf ] && SYSROM=$(grep -v '^#' /rom/etc/sysctl.conf | grep -v '^$' | tr '\n' ';')
info "sysctl.conf: live='${SYSLIVE}'  stock='${SYSROM}'"
if [ "$SYSLIVE" != "$SYSROM" ]; then warn "sysctl.conf differs from stock (scanners often raise fs.file-max; was this you?)"; fi
if [ -f /etc/.cfg ]; then info "/etc/.cfg ($(wc -c < /etc/.cfg) bytes):"; head -c 300 /etc/.cfg | cat -v | ind; fi
f="/root/postgres:.gz"
if [ -f "$f" ]; then
  info "$f: $(ls -l "$f" | awk '{print $5, $6, $7, $8}')"
  if gzip -t "$f" 2>/dev/null; then
    UNC=$(gzip -dc "$f" 2>/dev/null | wc -c)
    MAGIC=$(gzip -dc "$f" 2>/dev/null | head -c 4 | od -An -tx1 2>/dev/null | tr -d ' \n')
    info "  valid gzip, $UNC bytes uncompressed, first bytes: ${MAGIC:-unknown}"
    case "$MAGIC" in
      7f454c46) warn "  the archive contains an ELF executable" ;;
      68737173) info "  looks like a squashfs image (firmware dump)" ;;
      *)        info "  not an ELF; compare the size with your own firmware backups" ;;
    esac
  else
    warn "  not a valid gzip file"
  fi
fi
ls -la /root 2>/dev/null | ind

# ---------------------------------------------------------------- 10
hdr "10. Inode change times (cannot be forged from userland)"
info "A change time on Oct 7 before the flash finished means the file came with your setup; later means it was changed afterwards."
for f in /overlay/bank_*/etc/rc.local /overlay/bank_*/usr/sbin/dropbear /overlay/bank_*/etc/passwd /overlay/bank_*/etc/shadow /overlay/bank_*/root/dropbear.orig; do
  [ -e "$f" ] && ls -lc "$f" | ind
done

# ---------------------------------------------------------------- summary
W=$(tr -cd 'W' < "$CNT" | wc -c)
F=$(tr -cd 'F' < "$CNT" | wc -c)
rm -f "$REFF" "$CNT"
hdr "Summary"
printf 'FAIL=%s  WARN=%s\n' "$F" "$W"
if [ "$F" -eq 0 ]; then
  echo "No hard failures. Review each WARN: some are expected on a rooted router (modified dropbear, tchroot, rc.local line)."
else
  echo "There are FAIL lines above. Fix those first and send me the report."
fi
