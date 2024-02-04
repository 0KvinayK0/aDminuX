#!/usr/bin/env bash

echo -e "		       ######                         #     # "
echo -e "		  ##   #     # #    # # #    # #    #  #   #  "				
echo -e "		 #  #  #     # ##  ## # ##   # #    #   # #   "
echo -e "		#    # #     # # ## # # # #  # #    #    #    		A simple Linux administration automation tool!"
echo -e "		###### #     # #    # # #  # # #    #   # #   "
echo -e "		#    # #     # #    # # #   ## #    #  #   #  "
echo -e "		#    # ######  #    # # #    #  ####  #     # "

# Script will exit if it finds any arguments
if [[ $# -ge 1 ]]; then
    echo -e "\nThis script does not require or allow any arguments to run"
    exit 1
fi

# Script will exit if it is not executed with admin rights
if [[ "$EUID" -ne 0 ]]; then
    echo -e "\nPlease run this script with superuser privileges"
    echo "USAGE: sudo ./adminux.sh or sudo bash adminux.sh"
    exit 1
fi

# Array to store the menu
options=( "\n1. IP Blocker" "\n2. Network Uptime" "\n3. Manage Users" "\n4. Backup File" "\n5. Process Control" "\n6. Update System" "\n7. Quit")
echo -e "${options[@]}"

# Input from the user; using the -r flag to take \ as literal characters
read -p  "> Choose one option: " -r option

# Function for case insensitive comparison
input_lower_case(){
    option_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    echo "$option_lower"
}

# Declaring functions outside of their usage locations, as they may be used in multiple places

# Function to check if user-entered IP address(es) is valid
validate_single_ip(){

    # Changing the Local Internal Field Separator
    local IFS="."

    # Using regular expressions to determine if an IP address is valid
    if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then

        # Checking each octet
        read -r o1 o2 o3 o4 <<< "$1"
        if (( o1 >= 0 && o1 <= 255 )) &&
        (( o2 >= 0 && o2 <= 255 )) &&
        (( o3 >= 0 && o3 <= 255 )) &&
        (( o4 >= 0 && o4 <= 255 )); then

            return 0

        else
            return 1
        fi
    else
        return 1

    fi

    return 0

}

# Function to check if user-entered IP address(es) is/are valid
validate_multiple_ip(){

    # Storing the array elements in an variable
    local ips=("$@")

    for ip in "${ips[@]}"; do
        validate_single_ip "$ip"

        if [[ $? -ne 0 ]]; then
            return 1
        fi
    done

    return 0

}


check_case=$(input_lower_case "$option")

# Parent if condition for triggering IP Blocker option
if [[ "$option" == "1" || "$check_case" == "ip blocker"  ]]; then

    echo -e "\n[+] You have entered option 1"
    #echo "================================================================================="
    echo "[INFO] This allows you to drop packets from a single IP address, a range of IP addresses, or a file containing a list of IP addresses."
    #echo "================================================================================="
    echo "[+] This will only drop packets from the system that is executing the script"
    #echo "================================================================================="
    echo "[NOTE] Dropping packets using iptables is not persistent. Changes will be lost if the system is restarted. This should only be used to drop packets at the time of running and not as a standalone parameter."
    #echo "================================================================================="

    # Function to drop the packets
    drop_packets(){
        # Command to drop the packets
        iptables -I INPUT -s "$1" -j DROP
    }

    # Function to append IP address(es) passed as an argument to a file
    append_ip_file(){

        if [[ -n "$1" ]]; then

            # The output of the IP address will be added to a file in the current directory
            output="$( echo "$1" >> "blocked_ip_$(date +"%d%m%Y_%S")")"
            # echo "$output"

            if [[ $? -eq 0 ]]; then

                # The below message will only be displayed once
                if [[ ! -v DISPLAYED ]]; then
                    echo "[+] The IP addresses were successfully added to the file"
                    echo "================================================================================="
                    echo "[NOTE] The file format is in DDMMYYYY_SS, which is the current date and time. The SS will append the current seconds to prevent modification of existing files"
                    echo "================================================================================="
                    declare -g DISPLAYED=1
                fi
                return 0
            else
                echo "[-] There was a problem when adding the IP addresses to $output"
                return 1
            fi
        else
            echo "[-] There was an issue parsing the IP address $1"
            return 1
        fi
    }


    # Function to segregate appending IP to a file
    ask_add_file(){

        local ip="$1"
        read -p "> Do you want to add the blocked IP address to a file? [y/n]: " -r add_file

        while [[ "$add_file" != "y" && "$add_file" != "n" ]]; do
            echo "[-] Not quite. Try again?"
            read -p "> Do you want to add the blocked IP address to a file? [y/n]: " -r add_file

        done


        if [[ "$add_file" == "y" ]]; then
            append_ip_file "$ip"

            if [[ $? -eq 0 ]]; then
                return 0
            else
                echo "[-] It appears there was an error"
                return 1
            fi

        elif [[ "$add_file" == "n" ]]; then
            exit 0


        fi

    }

    # Function to segregate appending IP addresses to a file
    ask_add_multiple_file(){

        local ips=("$@")
        read -p "> Do you want to add the blocked IP addresses to a file? [y/n]: " -r add_file

        while [[ "$add_file" != "y" && "$add_file" != "n" ]]; do
            echo "[-] Not quite. Try again?"
            read -p "> Do you want to add the blocked IP addresses to a file? [y/n]: " -r add_file

        done


        if [[ "$add_file" == "y" ]]; then
            for ip in "${ips[@]}"; do

                append_ip_file "$ip"

                if [[ $? -ne 0 ]]; then
                    return 1
                fi
            done

        elif [[ "$add_file" == "n" ]]; then
            exit 0

        fi
        return 0

    }



    # Function for processing single IP address blocking
    single_ip_blocker(){

        read -p "> Enter a single IP address: " -r single_ip

        while [[ -z "$single_ip" ]]; do
            echo "You know, I was really looking forward to staring at this empty screen all day. Thank you for not disappointing me"
            read -p "> Enter a single IP address: " -r single_ip
        done

        # Calling the function to validate the IP address
        validate_single_ip "$single_ip"

        # Checking to see if the function executed successfully
        if [[ $? -eq 0 ]]; then
            echo "[+] Dropping packets from $single_ip..."

            drop_packets "$single_ip"

            if [[ $? -eq 0 ]]; then
                echo "[+] Packets from $single_ip were dropped successfully"

                ask_add_file "$single_ip"

            else
                echo "[-] There was a problem while dropping packets from $single_ip"
                return 1

            fi

        else
            echo "[-] Not an valid IP address"
            return 1
        fi
    }

    # Function for processing multiple IP address blocking
    multiple_ip_blocker(){

    while true; do
        read -p "> Enter multiple IP addresses separated by space: " -r -a multiple_ip

        if [[ "${#multiple_ip[@]}" -eq "0" ]]; then
            echo "Hey, it's not like I have anything better to do than wait for you to decide to actually do something"
        else
            validate_multiple_ip "${multiple_ip[@]}"

            if [[ $? -eq 0 ]]; then
                if [[ "${#multiple_ip[@]}" -eq "1" ]]; then
                    echo "[-] You can use 'Block single IP address', it is used to block a single IP"

                elif [[ "${#multiple_ip[@]}" -ge "10" ]]; then
                    echo "[-] It will be very efficient if you can use the 'Block IP addresses from a file' option"

                else
                    for ip in "${multiple_ip[@]}"; do
                        drop_packets "$ip"

                        if [[ $? -ne 0 ]]; then
                            echo "[-] There was a problem dropping packets for IP address $ip"
                            return 1
                        else
                            echo "[+] Dropped packets from IP address $ip successfully"
                        fi
                    done

                    ask_add_multiple_file "${multiple_ip[@]}"
                    return 0
                fi

            else
                echo "[-] Your input contains an invalid IP address"
                return 1
            fi
            break
        fi
    done
}


    # Function for processing multiple IP address blocking where input is from a file
    file_ip_blocker(){
        echo "================================================================================="
        echo "[NOTE] The file should contain each IP address on a separate line"
        echo "================================================================================="
        read -p "> Please enter the file containing the list of IP addresses: " -r file_ip

        while true; do

            if [[ -z "$file_ip" ]]; then
                echo "Wow, entering nothing, how very creative of you"
                read -p "> Please enter the file containing the list of IP addresses: " -r file_ip


            elif [[ ! -f "$file_ip" ]]; then
                echo "[-] Invalid file name: $file_ip"
                read -p "> Please enter the file containing the list of IP addresses: " -r file_ip

            elif [[ -n "$file_ip" ]]; then
                break
            fi

        done

        # Verifying that the input is a file and it exists.
        if [[ -f "$file_ip" ]]; then

            # An array to store IP addresses from a file
            declare -a file_ip_addr

            while read -r line; do
                file_ip_addr+=( "$line" )
            done < "$file_ip"

            validate_multiple_ip "${file_ip_addr[@]}"

            if [[ $? -eq "0" ]]; then
                for ip in "${file_ip_addr[@]}"; do
                    drop_packets "$ip"

                    if [[ $? -ne 0 ]]; then

                        echo "[-] There was a problem dropping packets for IP address $ip"
                        return 1
                    else
                        echo "[+] Dropped packets from IP address $ip successfully"

                    fi
                done

                ask_add_multiple_file "${file_ip_addr[@]}"
                return 0

            else
                echo "[-] The file \"$file_ip\" contains an invalid IP address"
                return 1
            fi
        else
            echo "[-] $file_ip is not an valid file"

        fi


    }

    # An array to store the sub-menu items for the IP blocker
    ip_blocker=( "\n1. Block single IP address" "\n2. Block multiple IP addresses" "\n3. Block IP addresses from a file" "\n4. Quit")
    echo -e "${ip_blocker[@]}"

    while true; do
        read -p "> Choose one option: " -r ip_option

        while [[ -z "$ip_option" ]]; do
            echo "Wow, the blank response, how original. I'm sure it will change the world"
            read -p "> Choose one option: " -r ip_option
        done

        check_case_ip_submenu=$(input_lower_case "$ip_option")
        if [[ "$ip_option" == "1" || "$check_case_ip_submenu" == "block single ip address" ]]; then
            single_ip_blocker
            break

        elif [[ "$ip_option" == "2" || "$check_case_ip_submenu" == "block multiple ip addresses" ]]; then
            multiple_ip_blocker
            break

        elif [[ "$ip_option" == "3" || "$check_case_ip_submenu" == "block ip addresses from a file" ]]; then
            file_ip_blocker
            break

        elif [[ "$ip_option" == "4" || "$check_case_ip_submenu" == "quit" ]]; then
            exit 0

        else
            echo "Gee, I had no idea that randomly punching keys on your keyboard could be considered a valid form of input. My mistake"

        fi
    done

    # Parent if condition for triggering Network Uptime option
elif [[ "$option" == "2" || "$check_case" == "network uptime"  ]]; then

    echo -e "\n[+] You have entered option 2"
    echo "[INFO] This allows you to verify if a host or IP address is connected to the Internet. You can add multiple IP addresses"
    echo -e "[INFO] You can enter either an absolute or a relative path name\n"

    process_validate_ping_ip(){

        # An array to store IP addresses from a file
        declare -a network_ip_arr

        # Iterating over the file input and storing them in an array
        while read -r line; do
            network_ip_arr+=( "$line" )
        done < "$1"

        # Calling the function with the IP addresses stored in the array
        validate_multiple_ip "${network_ip_arr[@]}"

        if [[ $? -eq "0" ]]; then
            #if [[ mycmd ]]; then

            # Printing the current date and time before executing the command, and appending the result to the log file
            echo "---------------------------$(date +"%d %B %Y %T" | awk -F: '{print $1 ":" $2}')---------------------------" >> "$2"

            for ip in "${network_ip_arr[@]}"; do

                # Storing the ping command output in an variable, pinging once, and timeout of one second
                output="$(ping -c1 "$ip" -W1)"

                # Validating the output of ping command
                if [[ "$output" == *"100% packet loss"* ]]; then
                    echo "[-] The IP address $ip given is not connected to the internet" >> "$2"

                else
                    echo "[+] The IP address $ip is connected to the internet" >> "$2"
                fi
            done

            echo "----------------------------------------------------------------------------" >> "$2"

        else
            echo "[-] The file \"$1\" contains an invalid IP address"
            exit 1
        fi

        echo "[+] The IP addresses have been successfully added to the file: $log_file"
        return 0

    }

    # Function for validating both user input files and calling the process_validate_ping_ip function
    validate_file() {

        local file_prompt=$1
        local file_name=$2
        local error_message=$3

        read -p "> $file_prompt: " -r $file_name

        while [[ -z "${!file_name}" ]]; do
            echo "I was hoping for a challenge, but this blank response is just too easy"
            read -p "> $file_prompt: " -r $file_name
        done

        while [[ ! -f "${!file_name}" ]]; do
            echo "$error_message: ${!file_name}"
            read -p "> $file_prompt: " -r $file_name
        done
    }

    # Validate the IP addresses file
    validate_file "> Enter a file containing IP addresses, each on a separate line" network_ip_file "Invalid IP address file"

    # Validate the log file
    validate_file "> Enter a filename to save IP addresses as a log entry (Create an empty file before running)" log_file "Invalid log file"

    # Calling the function to process and ping the IP addresses. The first argument is the file containing the IP addresses, and the second is the log file
    process_validate_ping_ip "$network_ip_file" "$log_file"

    # Parent if condition for triggering Manage Users options

elif [[ "$option" == "3" || "$check_case" == "manage users"  ]]; then

    echo -e "\n[+] You have entered option 3"
    
    # Function for adding single user
    add_single_user(){

        read -p "> Enter the username to add: " -r username

        # Validation of username
        while true; do

            if [[ -z "$username" ]]; then
                echo "Wow, the boldness of your silence is simply breathtaking! Although, I must admit, I do need just a bit more from you. Could you please add a response to this thrilling input adventure?"
                read -p "> Enter the username to add: " -r username
            elif ! [[ "$username" =~ ^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$ ]]; then
                echo "[-] Username can only contain alphanumeric characters and dashes"
                read -p "> Enter the username to add: " -r username
            elif [[ $(echo -n "$username" | wc -c) -gt 32 ]]; then
                echo "[-] Username must not exceed 32 characters"
                read -p "> Enter the username to add: " -r username
            else
                break
            fi
        done

        # Searching to see if the username entered is already present in the system
        present=$(grep -w "$username" /etc/passwd)

        if [[ -z $present ]]; then

            # Command to add the user with the home directory, and the bash shell
            sudo useradd -m -s /bin/bash "$username"

            if [[ $? -ne 0 ]]; then
                echo "[-] There was an issue adding the user"
                exit 1
            else
                echo "------------------------------------------------"
                echo "[+] Created $username home directory"
                echo "[+] Assigned the shell"
                echo "[+] The user $username has been added succesfully"
                echo "------------------------------------------------"
                exit 0
            fi
        else
            echo "[-] The user is already present"
            grep -w "$username" /etc/passwd
            exit 1
        fi
    }

    # Function for adding single or multiple users and groups
    add_user_group(){

        echo "[+] This allows you to add multiple users with their groups to the system. The input should be a file wherein users and groups are seperated by space and each combination is on a new line"
        echo "[+] EXAMPLE FILE CONTENTS:"
        echo "1 bob shinobi"
        echo "2 alice engineer"
        echo "[NOTE] This will create a new group in the /etc/group directory and add the user with that group. It should not be used to add an user to an existing group. To do that, please DuckDuckGo"

        read -p "> Enter the file that contains the user group combinations, separated by spaces: " -r user_group

        # Validation of file
        while true; do

            if [[ -z "$user_group" ]]; then
                echo "Nothing to say? That's okay, sometimes it's nice to just listen"
                read -p "> Enter the file that contains the user group combinations, separated by spaces: " -r user_group


            elif [[ ! -f "$user_group" ]]; then
                echo "[-] Invalid file name: $user_group"
                read -p "> Enter the file that contains the user group combinations, separated by spaces: " -r user_group

            elif [[ -n "$user_group" ]]; then
                break
            fi

        done

        if [[ -f "$user_group" ]]; then

            # An array to store user and groups from a file
            declare -a accounts

            while read -r line; do
                accounts+=( "$line" )
            done < "$user_group"


            for account in "${accounts[@]}"; do

                # Iterating over each user and storing in an variable
                user="$(echo "$account" | awk '{print $1}')"

                # Iterating over each group and storing in an variable
                group="$(echo "$account" | awk '{print $2}')"


                # The below message will only be displayed once
                if [[ ! -v DISPLAYED ]]; then

                    # Validating if each user and group contains correct strings
                    if ! [[ "$user" =~ ^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$ ]] || ! [[ "$group" =~ ^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$ ]]; then
                        echo "[-] Username or group can only contain alphanumeric characters and dashes. Please run the script again with the correct information"
                        declare -g DISPLAYED=1
                    elif [[ $(echo -n "$user" | wc -c) -gt 32 ]]; then
                        echo "[-] Username must not exceed 32 characters"
                        break
                    elif [[ $(echo -n "$group" | wc -c) -gt 32 ]]; then
                        echo "[-] Group length must not exceed 32 characters"
                        break

                    else
                        # Checking if the group already exists
                        group_exist="$(cat /etc/group | grep $group)"

                        if [[ -z $group_exist ]]; then

                            # Adding to system group
                            groupadd "$group"

                            if [[ $? -eq 0 ]]; then
                                echo "[+] The $group group was added successfully"
                            else
                                echo "[-] There was an error adding the group"
                                exit 1
                            fi
                        else
                            echo "[-] The group $group already exists"
                            exit 1
                        fi

                        # Checking if the user already exists
                        user_exist="$(cat /etc/passwd | grep $user)"

                        if [[ -z $user_exist ]]; then

                            # Creating the user
                            useradd -m -s /bin/bash -g "$group" "$user"

                            # Adding the user to the group
                            usermod -a -G $group $user

                            if [[ $? -eq 0 ]]; then
                                echo "[+] User $user was added successfully"
                            else
                                echo "[-] There was an error adding the user"
                                exit 1
                            fi
                        else
                            echo "[-] The user $user already exists"
                            exit 1
                        fi
                    fi
                fi
            done
        fi
    }

    # Function for deleting single user
    delete_single_user() {

        read -p "> Enter the username to delete: " user_del

        # Validation of username
        while true; do

            if [[ -z "$user_del" ]]; then
                echo "You know what they say, 'Silence is golden.' But in this case, it's just a bit uncooperative. Could you please add a response to this thrilling input adventure?"
                read -p "> Enter the username to delete: " user_del
            elif ! [[ "$user_del" =~ ^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$ ]]; then
                echo "[-] Username can only contain alphanumeric characters and dashes"
                read -p "> Enter the username to delete: " user_del
            elif [[ $(echo -n "$user_del" | wc -c) -gt 32 ]]; then
                echo "[-] Username must not exceed 32 characters"
                read -p "> Enter the username to delete: " -r user_del
            else
                break
            fi
        done

        # check if the user exists
        present_d=$(grep -w "$user_del" /etc/passwd)

        if [[ -n $present_d ]]; then

            # Deleting the user and it's home directory
            sudo userdel -r "$user_del" 2> /dev/null

            if [[ $? -ne 0 ]]; then
                echo "[-] There was an issue deleting the user"
                exit 1
            else
                echo "------------------------------------------------"
                echo "[+] The user $user_del has been deleted successfully"
                echo "------------------------------------------------"
                exit 0
            fi
        else
            echo "[-] The user $user_del does not exist"
            exit 1
        fi
    }

    # Function for deleting single user and its associated group
    delete_user_group(){

        read -p "> Enter the username to delete: " -r get_user

        # Validation of username
        while true; do
            if [[ -z "$get_user" ]]; then
                echo "If you don't have anything to say, that's alright. I'll just keep humming my favorite tune until you're ready"
                read -p "> Enter the username to delete: " -r get_user

            elif ! [[ "$get_user" =~ ^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$ ]]; then
                echo "[-] Username can only contain alphanumeric characters and dashes"
                read -p "> Enter the username to delete: " -r get_user
            elif [[ $(echo -n "$get_user" | wc -c) -gt 32 ]]; then
                echo "[-] Username must not exceed 32 characters"
                read -p "> Enter the username to delete: " -r get_user
            else
                break
            fi
        done

        # Check if the user exists
        user_exist="$(cat /etc/passwd | grep $get_user)"

        if [[ -z $user_exist ]]; then

            echo "[-] The user $get_user does not exist"
            exit 1

        else

            # Get the user's primary group
            user_group=$(id -gn $get_user)

            # Check if the group is still in use by other users
            group_user_count="$(awk -F: '$1 == user_group {print $1}' /etc/group | wc -l)"

            # Delete the user
            sudo userdel -r "$get_user" 2> /dev/null

            if [[ $? -eq 0 ]]; then
                echo "[+] The user $get_user was deleted successfully"

            else
                echo "[-] There was an error deleting the user"
                exit 1

            fi

            if [[ $group_user_count -eq 0 ]]; then
                # Delete the group
                sudo groupdel $user_group 2> /dev/null

                if [[ $? -eq 0 ]]; then
                    echo "[+] The group $user_group was deleted successfully"

                else
                    echo "[-] There was an error deleting the group"
                    exit 1

                fi

            else
                echo "[-] The group $user_group is still in use by other users"

            fi
        fi

    }

    logged_user(){

        echo "[+] Finding the number of users logged in and their name in the current system..."

        logged_in=$(who | awk '{print $1}' | uniq)
        count_logged_in=$(who | wc -l)

        echo "================================================================================="
        echo "[+] Number of logged in users: $count_logged_in"
        echo -e "\nName"
        echo "------------------------------------------------"
        echo "$logged_in" | tr ' ' '\n'
    }

    manage_users=( "\n1. Add single user" "\n2. Add users and groups" "\n3. Delete single user" "\n4. Delete user and group" "\n5. View logged in users ""\n6. Quit")
    echo -e "${manage_users[@]}"

    while true; do
        read -p "> Choose one option: " -r user_option

        while [[ -z "$user_option" ]]; do
            echo "Oh, the mighty silence. It speaks volumes, but I'm afraid I still need an actual input from you to proceed. Care to add some words to your bravery?"
            read -p "> Choose one option: " -r user_option
        done

        check_case_user_submenu=$(input_lower_case "$user_option")
        if [[ "$user_option" == "1" || "$check_case_user_submenu" == "add single user" ]]; then
            add_single_user
            break

        elif [[ "$user_option" == "2" || "$check_case_user_submenu" == "add users and groups" ]]; then
            add_user_group
            break

        elif [[ "$user_option" == "3" || "$check_case_user_submenu" == "delete single user" ]]; then
            delete_single_user
            break

        elif [[ "$user_option" == "4" || "$check_case_user_submenu" == "delete single group" ]]; then
            delete_user_group
            break

        elif [[ "$user_option" == "5" || "$check_case_user_submenu" == "view logged in users" ]]; then
            logged_user
            break

        elif [[ "$user_option" == "6" || "$check_case_user_submenu" == "quit" ]]; then
            exit 0

        else
            echo "Ah, the daring random string. It's bold and creative, but I'm afraid it's not quite what I was looking for. Could you please enter a valid input so we can proceed?"

        fi
    done

elif [[ "$option" == "4" || "$check_case" == "backup file"  ]]; then
   
    echo -e "\n[+] You have entered option 4"
    echo "[+] This can be used to create backup files within directories for the entire year"
    echo "[+] These files can be used to store data periodically"
    echo "[+] A use case: You are asked to create a backup file for every day of every month so the backup data can be stored"

    default_daily_backup(){

        echo -e "\n[+] Creating backup files (\"log.daily\") each day for every month of the year..."
        echo "------------------------------------------------"
        echo "[+] Creating current year directory and switching to it.."
        sleep 1

        current_year=$(date +%Y)
        mkdir -p $current_year; cd $current_year
        echo "------------------------------------------------"

        if [[ $? -eq 0 ]]; then
            echo "[+] Using brace expansion to create directories for each day of every month..."
            sleep 1

            sudo mkdir -p {January/{01..31},February/{01..28},March/{01..31},April/{01..30},May/{01..31},June/{01..30},July/{01..31},August/{01..31},September/{01..30},October/{01..31},November/{01..30},December/{01..31}}
            echo "------------------------------------------------"

            if [[ $? -eq 0 ]]; then
                echo "[+] Using brace expansion to create backup files for each day of every month..."
                sleep 1
                touch {January/{01..31}/log.daily,February/{01..28}/log.daily,March/{01..31}/log.daily,April/{01..30},May/{01..31}/log.daily,June/{01..30}/log.daily,July/{01..31}/log.daily,August/{01..31}/log.daily,September/{01..30}/log.daily,October/{01..31}/log.daily,November/{01..30}/log.daily,December/{01..31}/log.daily}
                echo "------------------------------------------------"

                if [[ $? -eq 0 ]]; then
                    echo "[+] Done. Your backup directory is $current_year (Try using 'tree $current_year' command for better view)"
                else
                    echo "[-] There was an issue creating the files"
                    exit 1
                fi

            else
                echo "[-] There was an issue creating the directories"
                exit 1

            fi

        else
            echo "[-] There was an issue running the command"
            exit 1

        fi
    }


    default_daily_backup

elif [[ "$option" == "5" || "$check_case" == "process control"  ]]; then

    echo -e "\n[+] You have entered option 5"
      
    tl_dr_view(){

        echo -e "\nDisplaying the top 10 processes with the highest CPU usage"
        echo "----------------------------------------------------------------"

        # Display the top 10 processes with the highest usage, sorted by CPU and memory usage
        ps -eo pid,%cpu,%mem,comm --sort=-%cpu,-%mem | head -n 11

    }

    bird_eye_view(){

        echo -e "\nDisplaying all the processes"
        echo "------------------------------------------------------------------------------------------------"

        # Display the top 10 processes with the highest usage, sorted by CPU and memory usage
        ps aux

    }

    kill_process(){
        # Store the minimum PID possible
        pid_min=1

        # Store the maximum PID possible
        pid_max=$(echo "2^16-1024" | bc)

        # Validation checks
        while true; do
            read -p "> Enter the process ID to kill: " -r process_id
            if [[ "$process_id" =~ ^[0-9]+$ ]]; then

                if (( process_id >= pid_min && process_id <= pid_max )); then
                    local check=$(ps -p "$process_id" -o pid )
                    if [[ -n "$check" ]]; then
                        echo "[+] Killing process $process_id"
                        echo "----------------------------------------------------"

                        # Command to terminate the process
                        kill -9 "$process_id"

                        if [[ $? -eq 0 ]]; then
                            echo "[+] Process ID $process_id killed successfully"
                        else
                            echo "[-] There was a problem in killing process id: $process_id"
                            return 1
                        fi

                    else
                        echo "[-] Process $process_id not found"
                    fi
                    break
                else
                    echo "[-] Invalid process ID. Please enter a valid process ID between $pid_min and $pid_max."
                fi
            else
                echo "[-] Invalid process ID. Please enter a valid process ID consisting of numbers only."
            fi
        done

    }

    process_monitor(){

	echo -e "\n[+] Monitor your system with this option if a process is using a lot of CPU and memory"
	echo "[+] Run this script in a separate window. It will check every 60 seconds and alert you when any process reaches the specified usage threshold"
        
        while true; do

            read -p "> Enter a list of processes to monitor (seperated by spaces): " -r -a PROCESSES

            # Validating input
            if [ -z "${PROCESSES[@]}" ]; then
                echo "[-] Process list cannot be empty"
            else
                invalid_processes=()
                for proc in "${PROCESSES[@]}"; do
                    if ! pgrep -x "$proc" >/dev/null; then
                        invalid_processes+=("$proc")
                    fi
                done

                if [ ${#invalid_processes[@]} -ne 0 ]; then
                    echo "[-] Invalid process(es): ${invalid_processes[*]}"
                else
                    break
                fi
            fi
        done

        # Asking the user for CPU and memory usage thresholds
        while true; do
            echo "> Enter the CPU usage threshold (in percent, between 1 and 100): "
            read CPU_THRESHOLD

            # Validate CPU threshold input
            if [[ "$CPU_THRESHOLD" =~ ^[0-9]+$ ]] && (( "$CPU_THRESHOLD" >= 1 )) && (( "$CPU_THRESHOLD" <= 100 )); then
                break
            elif [[ -z "$CPU_THRESHOLD" ]]; then
                echo "Looks like we have a classic 'silent treatment' scenario here. Let's break the silence - could you please provide the necessary input?"
            else
                echo "[-] Invalid input. Please enter a number between 1 and 100"
            fi
        done

        while true; do
            echo "> Enter the memory usage threshold (in percent, between 1 and 100): "
            read MEM_THRESHOLD

            # Validate memory threshold input
            if [[ "$MEM_THRESHOLD" =~ ^[0-9]+$ ]] && (( "$MEM_THRESHOLD" >= 1 )) && (( "$MEM_THRESHOLD" <= 100 )); then
                break
            elif [[ -z "$MEM_THRESHOLD" ]]; then
                echo "It appears we have a communication breakdown - I need you to speak up (or type up), please!"
            else
                echo "[-] Invalid input. Please enter a number between 1 and 100"
            fi
        done

        echo "[+] Monitoring processes. Press Ctrl+C to exit"
        while true; do
            # Display waiting message
            echo -ne "[+] Waiting... $(date +"%r")\r"

            for proc in "${PROCESSES[@]}"; do
                # Get process information using ps and filter by name
                proc_info=$(ps -C $proc -o %cpu,%mem --no-headers | awk '{print $1,$2}')

                # Checking the CPU and memory usage
                cpu_usage=$(echo $proc_info | cut -d " " -f 1)
                mem_usage=$(echo $proc_info | cut -d " " -f 2)

                if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )) || (( $(echo "$mem_usage > $MEM_THRESHOLD" | bc -l) )); then
                    echo "[-] Process $proc has exceeded the CPU or memory usage threshold!"

                fi
            done

            # Waiting for a certain amount of time before checking again
            sleep 60
        done
    }

    # Main menur for interacting with process options
    process_control=( "\n1. List processes"  "\n2. Kill process" "\n3. Process monitor" "\n4. Quit")
    echo -e "${process_control[@]}"

    while true; do
        read -p "> Choose one option: " -r process_opt

        while [[ -z "$process_opt" ]]; do
            echo "It looks like you didn't provide an input. No worries, I'm here to help! Could you please provide the required input so we can continue?"
            read -p "> Choose one option: " -r process_opt
        done

        check_case_process_submenu=$(input_lower_case "$process_opt")

        if [[ "$process_opt" == "1" || "$check_case_process_submenu" == "list processes" ]]; then

            # Sub menu under list processes
            list_process=( "\n1. TL;DR view"  "\n2. Bird eye view" "\n3. Quit")
            echo -e "${list_process[@]}"

            while true; do
                read -p "> Choose one option: " -r process_list_opt

                while [[ -z "$process_list_opt" ]]; do
                    echo "It seems like you haven't entered anything. Please provide an input"
                    read -p "> Choose one option: " -r process_list_opt
                done

                check_case_process_list_submenu=$(input_lower_case "$process_list_opt")

                if [[ "$process_list_opt" == "1" || "$check_case_process_list_submenu" == "tl;dr view" ]]; then
                    tl_dr_view
                    break

                elif [[ "$process_list_opt" == "2" || "$check_case_process_list_submenu" == "bird eye view" ]]; then
                    bird_eye_view
                    break

                elif [[ "$process_list_opt" == "3" || "$check_case_process_list_submenu" == "quit" ]]; then
                    exit 0

                else
                    echo "[-] Your input is not recognized. Please try again with a valid input"

                fi

            done

            break

        elif [[ "$process_opt" == "2" || "$check_case_process_submenu" == "kill process" ]]; then
            kill_process
            break

        elif [[ "$process_opt" == "3" || "$check_case_process_submenu" == "process monitor" ]]; then
            process_monitor
            break

        elif [[ "$process_opt" == "4" || "$check_case_process_submenu" == "quit" ]]; then
            exit 0

        else
            echo "Oops, it looks like the input you provided is not valid. Let's try again!"

        fi
    done

elif [[ "$option" == "6" || "$check_case" == "update system"  ]]; then

   echo -e "\n[+] You have entered option 6"

    echo -e "\nUpdating system..."; sudo apt update -y && sudo apt upgrade -y && sudo apt clean -y

    if [[ $? -eq 0 ]]; then
        echo "[+] Update completed successfully"
    else
        echo "[-] There was an error updating the system"
    fi

elif [[ "$option" == "7" || "$check_case" == "quit"  ]]; then
    exit 0
else
    echo "We've just begun, and you've already entered the wrong prompt. This should be interesting!"

fi
