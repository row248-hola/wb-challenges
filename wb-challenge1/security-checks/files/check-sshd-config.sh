#!/bin/bash 

check_sshd_config() {
    dangerous_settings=$(grep -E '^PermitEmptyPasswords yes|^Protocol 1$' /etc/ssh/sshd_config)
    if [ "$dangerous_settings" != "" ]; then
        printf 'Found dangerous settings in /etc/ssh/sshd_config:\n%s' "$dangerous_settings"
    fi
}

check_sshd_config