#! /bin/bash

check_vulnerabilities(){
    python3 sg_check.py
    if [ $? -eq "0" ]; then
        send_mail 
    else
        exit 1
    fi
}

send_mail(){
    body="/tmp/body.txt"
    to = "repo_system@outlook.com"
    cat $body | grep "Warning: found potentail security hole" > /dev/null
    if [ $? -eq "0" ]; then
        echo -e "\e[92mSending mail --->\e[0m"
        cat $body | mutt -s "Security Groups vulnerabilities issues" $to
    else
        echo "No Security Groups vulnerabilities issues is founds" | mutt -s "Security Groups vulnerabilities issues" $to
    fi
}
#devops@otoma.com
main(){
    # First Check to validate if mail service is installd!
    dpkg -l mutt postfix > /dev/null
    if [ $? -eq "0" ]; then
        check_vulnerabilities
    else    
        sudo apt-get update && sudo apt-get -y install postfix mutt
        sudo mkfifo /var/spool/postfix/public/pickup
        service postfix restart
        check_vulnerabilities
    fi  
}
main