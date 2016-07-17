#!/usr/bin/python
import sys
import time
import urllib2
import urllib
import json

VIRUSTOTAL_API2_KEY = 'a8265f6e0696413e304ee2744eb0ed93b52f72b7f7f0b2bfd2acdde3e67ee6cf'
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
hash_list = []
counter = 0

in_file = open(sys.argv[1],'r')
for line in in_file:
        hash_list.append(line)
in_file.close

for searchTerm in hash_list:
	counter = counter + 1
	webForms = {'resource':searchTerm,'apikey':VIRUSTOTAL_API2_KEY}
	req = urllib2.Request(VIRUSTOTAL_REPORT_URL,urllib.urlencode(webForms))
	hRequest = urllib2.urlopen(req, timeout=15)
	data = hRequest.read()
	data = json.loads(data)

	try:
		pos = data['positives']
		total = data['total']
		url = data['permalink']
		comment = data['verbose_msg']
		hash = data['md5']
		date = data['scan_date']
		result = "%s / %s" % (pos,total)

		print hash + ',' + result + ',' + date + ','  + url + ',' + comment
		time.sleep(1)

	except:
		print data['resource'] + " is not indexed on virustotal"
		time.sleep(1)

	if (counter % 4) == 0:
		time.sleep(15)

