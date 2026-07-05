#!/bin/bash
read -p "Create new instance username: " username
read -p "Create new instance password: " password
python3 -c "import bcrypt; print(bcrypt.hashpw(b'$username:$password',bcrypt.gensalt()).decode())">creds
echo -e "\nYou can create a free Gemini API key in Google AI Studio\n(https://aistudio.google.com/)"
read -p "Enter Gemini API key: " apikey
echo $apikey>>creds