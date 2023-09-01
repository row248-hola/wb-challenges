#!/bin/bash 

check_file_permissions() {
    check_bits() {
        file_to_check="$1"
        required_bits="$2"
        file_bits=$(stat -c "%a" "$file_to_check")

        if [ "$file_bits" != "$required_bits" ]; then
            echo "bad file permission for $file_to_check, required bits=$required_bits but actual bits=$file_bits"
        fi
    }

    check_bits "/etc/shadow" 640

    while read -r file; do
        check_bits "$file" 600
    done < <(find /home/*/.ssh/* /root/.ssh/* -not -name "*.pub" &>/dev/null)

    while read -r file; do
        check_bits "$file" 644
    done < <(find /home/*/.ssh/* /root/.ssh/* -name "*.pub" &>/dev/null)
}

check_file_permissions