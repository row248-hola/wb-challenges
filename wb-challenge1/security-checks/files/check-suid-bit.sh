#!/bin/bash 

# Checks all binaries from https://gtfobins.github.io/#+suid

check_suid_bit() {
    binary_list="aa-exec$|ab$|agetty$|alpine$|ar$|arj$|arp$|as$|ascii-xfr$|ash$|aspell$|atobm$|awk$|base32$|base64$|basenc$|basez$|bash$|bc$|bridge$|busybox$|bzip2$|cabal$|capsh$|cat$|chmod$|choom$|chown$|chroot$|cmp$|column$|comm$|cp$|cpio$|cpulimit$|csh$|csplit$|csvtool$|cupsfilter$|curl$|cut$|dash$|date$|dd$|debugfs$|dialog$|diff$|dig$|distcc$|dmsetup$|docker$|dosbox$|ed$|efax$|elvish$|emacs$|env$|eqn$|espeak$|expand$|expect$|file$|find$|fish$|flock$|fmt$|fold$|gawk$|gcore$|gdb$|genie$|genisoimage$|gimp$|grep$|gtester$|gzip$|hd$|head$|hexdump$|highlight$|hping3$|iconv$|install$|ionice$|ip$|ispell$|jjs$|join$|jq$|jrunscript$|julia$|ksh$|ksshell$|kubectl$|ld.so$|less$|logsave$|look$|lua$|make$|mawk$|more$|mosquitto$|msgattrib$|msgcat$|msgconv$|msgfilter$|msgmerge$|msguniq$|multitime$|mv$|nasm$|nawk$|ncftp$|nft$|nice$|nl$|nm$|nmap$|node$|nohup$|od$|openssl$|openvpn$|pandoc$|paste$|perf$|perl$|pexec$|pg$|php$|pidstat$|pr$|ptx$|python$|rc$|readelf$|restic$|rev$|rlwrap$|rsync$|rtorrent$|run-parts$|rview$|rvim$|sash$|scanmem$|sed$|setarch$|setfacl$|setlock$|shuf$|soelim$|softlimit$|sort$|sqlite3$|ss$|ssh-agent$|ssh-keygen$|ssh-keyscan$|sshpass$|start-stop-daemon$|stdbuf$|strace$|strings$|sysctl$|systemctl$|tac$|tail$|taskset$|tbl$|tclsh$|tee$|tftp$|tic$|time$|timeout$|troff$|ul$|unexpand$|uniq$|unshare$|unzip$|update-alternatives$|uudecode$|uuencode$|vagrant$|view$|vigr$|vim$|vimdiff$|vipw$|w3m$|watch$|wc$|wget$|whiptail$|xargs$|xdotool$|xmodmap$|xmore$|xxd$|xz$|yash$|zsh$|zsoelim$"

    bad_suids=$(find / -perm -u=s -type f 2>/dev/null | grep -P $binary_list)
    if [ "$bad_suids" != "" ]; then
        echo "Bad SUID for ${bad_suids} binary. Read more at https://gtfobins.github.io/"
    fi
}

check_suid_bit