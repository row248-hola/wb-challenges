#!/bin/sh

docker build -t ubuntu .
docker stop wb-challenge1
docker run -i -p2222:22 --name wb-challenge1 --rm ubuntu &

echo "Accesss Ubuntu 20.04 via ssh at 127.0.0.1:2222 with user client:cient"
ansible-playbook -i hosts playbook.yml
echo "\nGenerated report report.txt\n" 
cat report.txt