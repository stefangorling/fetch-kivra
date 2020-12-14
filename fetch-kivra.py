#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import sys
import shutil
import os
import logging, sys
import time


"""
Url: https://gist.github.com/wassname/1393c4a57cfcbf03641dbc31886123b8
"""
import unicodedata
import string

valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
char_limit = 255

def clean_filename(filename, whitelist=valid_filename_chars, replace=' '):
    # replace spaces
    for r in replace:
        filename = filename.replace(r,'_')
    
    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()
    
    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in whitelist)
    if len(cleaned_filename)>char_limit:
        logging.warn("Warning, filename truncated because it was over {}. Filenames may no longer be unique".format(char_limit))
    return cleaned_filename[:char_limit]    


logging.basicConfig(stream=sys.stderr, level=logging.INFO)

client_id="14085255171411300228f14dceae786da5a00285fe"

session=requests.Session()

r= session.get("https://app.kivra.com/")

if len(sys.argv) != 2:
	sys.exit("Incorrect number of arguments, please supply personnummer: ./fetch-kivra.py YYYYMMDDXXXX")

r=session.post("https://api.kivra.com/v2/bankid",data={'ssn': sys.argv[1]})

logging.debug(r.status_code, r.reason)


if r.status_code != 201:
 sys.exit("failure creating auth request")

login_id=r.json()["bankid_order_key"]


status="pending"
while (status!="complete"):
    logging.info("Please sign in to Kivra app with BankId app")
    r=session.get("https://api.kivra.com/v2/bankid/"+login_id)
    logging.debug(r.status_code, r.reason)
    logging.debug(r.text[:300] + '...')
    logging.debug ("----")

    status=r.json()["status"]

    if (status=="pending"):
        time.sleep(5) 

    if (status!="pending" and status!="complete"):
        sys.exit("Unknown login status")
	


r=session.post("https://api.kivra.com/v1/auth",data={"grant_type":"implicit","client_id":client_id,"state":"intro","redirect_uri":"https://app.kivra.com/#/auth/kivra/return","bankid_order_key":login_id})
logging.debug(r.status_code, r.reason)
logging.debug(r.text[:300] + '...')
logging.debug ("----")

if r.status_code!=200:
    sys.exit("Login post failed")


data=r.json()

access_token=data['access_token']
user=data['resource_owner'].lstrip("user_")

logging.debug ("Access:"+access_token)
logging.debug ("user:"+user)


HEADERS = {'Authorization': "token {}".format(access_token)}
session.headers.update(HEADERS)


### Fetch Receipts (json only for now, until web renderer is available)
url="https://app.api.kivra.com/v1/user/"+user+"/receipts/list?limit=10000&offset=0"
r=session.get(url)

if r.status_code!=200:
	sys.exit("Failed to get receipt list")

data=r.json();
for receipt in data["receipts"]:
	logging.debug (receipt)
	logging.debug ("---")

	url="https://app.api.kivra.com/v1/user/"+user+"/receipts/"+receipt["receipt_id"]+"?via=auth_and_receipt_list"
	r=session.get(url)
	if r.status_code!=200:
		sys.exit("Failed to get receipt list")
	
	#Create document structure, one folder per sender.
	directory="receipts/"+clean_filename(receipt["store_name"])
	os.makedirs(directory,exist_ok=True)
	output=directory+"/"+clean_filename(receipt["purchase_date"]+"_"+receipt["store_name"])
	logging.info("saving: "+output)
	receipt_file=open(output,"w")
	receipt_file.write(r.text)
	receipt_file.close()


### Fetch Documets (content)
r=session.get("https://app.api.kivra.com/v2/user/"+user+"/content/?")

if r.status_code!=200:
	sys.exit("Failed to get document list")

data=r.json();
for document in data:

	doc_content=session.get("https://app.api.kivra.com/v2/user/"+user+"/content/"+document["key"])
	if doc_content.status_code!=200:	
	   sys.exit("Failed to fetch raw file")

	logging.debug (doc_content.status_code,doc_content.reason)
	logging.debug (doc_content.text)

	for part in doc_content.json()["parts"]:

		if part["content_type"] in {"text/plain","text/html"} :
			logging.debug ("...skipping body type "+part["content_type"])
		elif part["content_type"] == "application/pdf":

			#Create document structure, one folder per sender.
			directory="documents/"+clean_filename(document["sender_name"])
			os.makedirs(directory,exist_ok=True)
			output=directory+"/"+clean_filename(document["created_at"]+"_"+document["sender_name"]+"_"+document["subject"]+"_"+part["name"])
			
			if not os.path.exists(output):
				url = "https://app.api.kivra.com/v1/user/"+user+"/content/"+document["key"]+"/file/"+part["key"]+"/raw"
				response = session.get(url, stream=True)
				logging.debug(response.status_code, response.reason)
				if response.status_code!=200:
	    				sys.exit("Failed to fetch raw file")

				logging.info("saving "+output)
				with open(output, 'wb') as out_file:
	    				shutil.copyfileobj(response.raw, out_file)

				del response
			else:
				logging.info (output+" already saved, ignoring")
		else:
			logging.error ("Err: unknown content type:"+part["content_type"]+", ignoring")









