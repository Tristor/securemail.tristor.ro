#!/usr/bin/env bash
#
# This script is inteded only to be used on a system which was configured
# following the instructions on http://securemail.tristor.ro/
# Please ensure the variables at the top are configured correctly before running.

# Database Configuration

DBHOST="127.0.0.1"
DBPORT="3306"
DBNAME="mailserver"
DBUSER="mailuser"
DBPASS=""
USERTABLE="virtual_users"
DOMAINTABLE="virtual_domains"

# Welcome message.
echo "Welcome! This script will assist you in adding a user to your email server.
"

# Print Domains
echo "We are going to retrieve a list of domains.  If this command fails, please check the script to ensure you have the correct database configuration."

DOMAINS="$(mysql -h ${DBHOST}:${DBPORT} -u ${DBUSER} -p${DBPASS} -D ${DBNAME} -t -e SELECT * FROM ${DOMAINTABLE};)"

echo ${DOMAINS}

# Get user input
echo "Select which domain you'd like to add the user to.  This prompt only accepts numeric ids."
read -e DOMAINID

# Sanitize inputs to only be numeric

CLEAN="${DOMAINID//[^0-9]/}"
DOMAINID="${CLEAN}"

# Verify user selection
DOMAIN="$(mysql -h ${DBHOST}:${DBPORT} -u ${DBUSER} -p${DBPASS} -D ${DBNAME} -r -e SELECT name FROM ${DOMAINTABLE} WHERE id = ${DOMAINID};)"

echo "You wished to add the user to: ${DOMAIN}.  Is that correct? [Y/n]"
# Default to "Yes"
RESPONSE="Y"
read -e RESPONSE
# Sanitize
CLEAN="${RESPONSE//[^A-Z]/}"
RESPONSE="${CLEAN}"

if [ "${RESPONSE}" != "Y" ]
    then
        echo "You've indicated you did not wish to continue.  Script terminating..."
        exit 1
fi

# Get User information

echo -e "\n\n"
echo "Okay.  Thanks for that information.  Now let's choose a username and password."
echo "First, what is the user you want to add?  Their address will become user@${DOMAIN}."
read -e USERNAME

# Sanitize
CLEAN="${USERNAME//[^a-zA-Z]/}"
USERNAME="${CLEAN}"

# Verify Choice
echo "The new email address will be ${USERNAME}@${DOMAIN}.  Is this correct? [Y/n]"
RESPONSE = "Y"
read -e RESPONSE
# Sanitize
CLEAN="${RESPONSE//[^A-Z]/}"
RESPONSE="{CLEAN}"

if [ "{RESPONSE}" != "Y" ]
    then
        echo "You've indicated that you did not wish to continue.  Script terminating..."
        exit 1
fi

# Get Password

echo -e "\n\n"
echo "Next, we need to create a password for this user.  Please use a strong password.  This will get stored as a SHA512 hash in the database so it's secure."

SHAPASS="$(doveadm pw -s SHA512-CRYPT | awk '{print substr($0,15)}')"

echo -e "\n"
echo "Storing results in database."

RESULTS="$(mysql -h ${DBHOST}:${DBPORT} -u ${DBUSER} -p${DBPASS} -D ${DBNAME} -t -e INSERT INTO ${USERTABLE} (domain_id, password, email) VALUES (${DOMAINID}, \"${SHAPASS}\",\"${USERNAME}@${DOMAIN}\");)"

echo -e "\n"
echo "${RESULTS}"

echo "$(mysql -h ${DBHOST}:${DBPORT} -u ${DBUSER} -p${DBPASS} -D ${DBNAME} -t -e SELECT * FROM ${USERTABLE} WHERE email = \"${USERNAME}@${DOMAIN}\";)"

echo "\n\n"
echo "Congratulations, you've added an additional user."
exit 0
