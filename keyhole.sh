#!/bin/bash


# echo "Enter Directory: "
read -e -p "Enter Key File: " keyfile
read -e -p "Enter User: " userpath
read -e -p "Enter Server: " serverpath
read -e -p "Enter Port: " portpath

# cat and copy
cat "$keyfile" | ssh -p "$portpath" -v "$userpath"@"$serverpath" 'cat - > .ssh/authorized_keys'
