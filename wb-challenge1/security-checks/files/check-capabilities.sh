#!/bin/bash 

# Checks all binaries from https://gtfobins.github.io/#+capabilities

check_capabilities() {
    binary_list="gdb|node|perl|php|ruby|rview|rvim|view|vim|vimdiff|python"
    risky_capabilities="cap_sys_admin|cap_setgid|cap_setuid"

    bad_suids=$(getcap -r / 2>/dev/null | grep -P "$binary_list" | grep -P "$risky_capabilities")
    if [ "$bad_suids" != "" ]; then
        echo "Possible risky capabilities for ${bad_suids} binary. Read more at https://gtfobins.github.io/"
    fi
}

check_capabilities