#!/bin/sh

set -e

tld="test-$(openssl rand 5 -base64 | tr -d '=')"
mkdir -p ${tld}/states/state1/test 

cp test_salt_state.py $tld
cp config.json $tld
touch ${tld}/states/state1/init.sls

for i in ${tld}/grains.json ${tld}/states/state1/test/pillar.json
do
	echo '{
	    "local": {}
		 }' > ${i}; done

