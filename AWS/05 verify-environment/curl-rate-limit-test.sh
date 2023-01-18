#!/bin/bash
rate=150
url=https://<host>/service-login.php
for i in $(eval echo {1..$rate})
do
  # echo rate
  curl --location --request POST $url \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Cookie: PHPSESSID=<session id>' \
    --data-urlencode 'request={"operation":"login","username":"doesnotexist","password":"doesnotexist"}'  
  echo ''
  sleep 1
done

#for ($num = 1 ; $num -le 200 ; $num++) {Invoke-WebRequest -Uri $url}
