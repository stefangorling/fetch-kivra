#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import sys
import shutil
import os
import logging, sys
import time
import qrcode
from PIL import Image
import base64
import hashlib
import secrets
import json


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

def format_date(iso_date):
    """Konvertera ISO-datum till YYYY-MM-DD format"""
    return iso_date.split('T')[0] if iso_date else 'unknown_date'

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# Skapa temp-mapp för QR-kod och andra temporära filer
script_dir = os.path.dirname(os.path.abspath(__file__))
temp_dir = os.path.join(script_dir, "temp")
os.makedirs(temp_dir, exist_ok=True)

client_id="14085255171411300228f14dceae786da5a00285fe"

session=requests.Session()

r= session.get("https://app.kivra.com/")

if len(sys.argv) != 2:
    sys.exit("Incorrect number of arguments, please supply personnummer: ./fetch-kivra.py YYYYMMDDXXXX")
ssn = sys.argv[1]

# Konfiguration
FETCH_RECEIPTS = True  # Sätt till True för att hämta kvitton
FETCH_LETTERS = True    # Sätt till True för att hämta brev

# Uppdaterad BankID-initiering och QR-hantering
def display_qr_code(qr_data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    # Skapa och spara QR-koden som en temporär bild i temp-mappen
    img = qr.make_image(fill_color="black", back_color="white")
    temp_path = os.path.join(temp_dir, "kivra_qr.png")
    img.save(temp_path)
    
    # Öppna bilden med systemets standardbildvisare
    try:
        Image.open(temp_path).show()
        print("\nQR-kod visas nu. Skanna den med BankID-appen.")
        print("QR-koden har också sparats som:", temp_path)
    except Exception as e:
        logging.error(f"Kunde inte visa QR-kod: {e}")
        print(f"QR-kod sparad som '{temp_path}'")
    
    return temp_path

def generate_code_verifier():
    code_verifier = secrets.token_urlsafe(32)
    return code_verifier

def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').rstrip('=')
    return code_challenge

# Generera code_verifier och code_challenge
code_verifier = generate_code_verifier()
code_challenge = generate_code_challenge(code_verifier)

# OAuth2 initiering med exakta parametrar
auth_url = "https://app.api.kivra.com/v2/oauth2/authorize"
auth_params = {
    'response_type': 'bankid_all',
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256',
    'scope': 'openid profile',
    'client_id': '14085255171411300228f14dceae786da5a00285fe',
    'redirect_uri': 'https://inbox.kivra.com/auth/kivra/return'
}

# Lägg till mer detaljerad loggning
logging.info("Försöker initiera OAuth2 med följande parametrar:")
logging.info("URL: %s", auth_url)
logging.info("Parametrar: %s", auth_params)

r = session.post(auth_url, 
                 json=auth_params,
                 headers={
                     'Content-Type': 'application/json',
                     'Accept': 'application/json',
                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                 })

logging.info("Status kod: %d", r.status_code)
logging.info("Response headers: %s", dict(r.headers))
logging.info("Response body: %s", r.text)

if r.status_code not in [201, 202]:
    logging.error("Fel vid OAuth2 authorize. Status: %d, Response: %s", r.status_code, r.text)
    sys.exit("Kunde inte initiera OAuth2")

try:
    auth_data = r.json()
    qr_code = auth_data.get('qr_code')
    next_poll_url = auth_data.get('next_poll_url')
    auth_code = auth_data.get('code')  # Spara auth_code från authorize-svaret
    
    logging.debug("Auth data: %s", auth_data)
    
    if not qr_code:
        logging.error("QR-kod saknas i svaret: %s", auth_data)
        sys.exit("Kunde inte hämta QR-kod från Kivra")
    
    if not auth_code:
        logging.error("Auth code saknas i svaret: %s", auth_data)
        sys.exit("Kunde inte hämta auth code från Kivra")

    # Visa QR-koden och spara sökvägen
    temp_path = display_qr_code(qr_code)
    print("\nQR-kod visas nu. Skanna den med BankID-appen.")

    # Vänta på autentisering genom att polla next_poll_url
    print("\nVäntar på BankID-scanning...")
    while True:
        time.sleep(5)
        poll_response = session.get(f"https://app.api.kivra.com{next_poll_url}")
        poll_data = poll_response.json()
        
        logging.debug("Poll response: %s", poll_data)
        
        if poll_data.get('status') == 'complete':
            print("\nBankID-autentisering lyckades!")
            
            # Använd auth_code som vi sparade från authorize-svaret
            token_url = "https://app.api.kivra.com/v2/oauth2/token"
            token_data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": "14085255171411300228f14dceae786da5a00285fe",
                "redirect_uri": "https://inbox.kivra.com/auth/kivra/return",
                "code_verifier": code_verifier
            }

            print("Hämtar OAuth token...")
            token_response = session.post(token_url, 
                                        json=token_data,
                                        headers={'Content-Type': 'application/json'})

            logging.debug("Token request data: %s", token_data)
            logging.debug("Token response status: %d", token_response.status_code)
            logging.debug("Token response: %s", token_response.text)

            if token_response.status_code != 200:
                logging.error("Kunde inte hämta token. Status: %d, Response: %s", 
                             token_response.status_code, token_response.text)
                sys.exit("Token-hämtning misslyckades")

            token_info = token_response.json()
            access_token = token_info.get('access_token')
            id_token = token_info.get('id_token')
            
            # Dekodera JWT (vi behöver bara payload-delen, del 2)
            id_token_parts = id_token.split('.')
            if len(id_token_parts) < 2:
                logging.error("Ogiltig id_token struktur")
                sys.exit("Kunde inte tolka id_token")
                
            # Dekodera base64
            import base64
            import json
            
            # Lägg till padding om det behövs
            padding = '=' * (4 - len(id_token_parts[1]) % 4)
            jwt_payload = base64.b64decode(id_token_parts[1] + padding)
            jwt_data = json.loads(jwt_payload)
            
            # Hämta kivra_user_id från JWT
            actor_key = jwt_data.get('kivra_user_id')
            
            if not actor_key:
                logging.error("Kunde inte hitta kivra_user_id i token: %s", jwt_data)
                sys.exit("Saknar kivra_user_id")
            
            logging.debug("Using access_token: %s", access_token)
            logging.debug("Using actor_key: %s", actor_key)
            
            # Definiera GraphQL URL och query
            graphql_url = "https://bff.kivra.com/graphql"
            
            # Definiera headers som används för både kvitton och brev
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Origin': 'https://inbox.kivra.com',
                'Referer': 'https://inbox.kivra.com/',
                'Authorization': f'Bearer {access_token}',
                'X-Actor-Key': actor_key,
                'X-Actor-Type': 'user',
                'X-Session-Actor': f'user_{actor_key}',
                'X-Kivra-Environment': 'production',
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
                'Accept-Language': 'sv',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            # Skapa huvudmapp för detta personnummer
            base_dir = os.path.join(script_dir, ssn)
            os.makedirs(base_dir, exist_ok=True)

            if FETCH_RECEIPTS:
                print("\nHämtar kvitton...")
                # Skapa Receipts-mapp och undermappar under personnummermappen
                receipts_dir = os.path.join(base_dir, "Receipts")
                json_dir = os.path.join(receipts_dir, "json")
                os.makedirs(receipts_dir, exist_ok=True)
                os.makedirs(json_dir, exist_ok=True)
                
                # GraphQL query för att hämta kvitton
                query = """
                query Receipts($search: String, $limit: Int, $offset: Int) {
                  receiptsV2(search: $search, limit: $limit, offset: $offset) {
                    __typename
                    total
                    offset
                    limit
                    list {
                      ...baseDetailsFields
                    }
                  }
                }

                fragment baseDetailsFields on ReceiptBaseDetails {
                  __typename
                  key
                  purchaseDate
                  totalAmount {
                    formatted
                  }
                  attributes {
                    isCopy
                    isExpensed
                    isReturn
                    isTrashed
                  }
                  store {
                    name
                    logo {
                      publicUrl
                    }
                  }
                  attachments {
                    id
                    type
                  }
                  accessInfo {
                    owner {
                      isMe
                      name
                    }
                  }
                }
                """

                graphql_payload = {
                    "operationName": "Receipts",
                    "query": query,
                    "variables": {
                        "limit": 20000,
                        "offset": 0,
                        "search": None
                    }
                }
                
                logging.debug("Request headers: %s", headers)
                
                response = session.post(graphql_url, 
                                      json=graphql_payload,
                                      headers=headers)

                logging.debug("GraphQL response status: %d", response.status_code)
                logging.debug("GraphQL response: %s", response.text)

                if response.status_code != 200:
                    logging.error("Kunde inte hämta kvittolista. Status: %d, Response: %s", 
                                response.status_code, response.text)
                    sys.exit("GraphQL-anrop misslyckades")

                data = response.json()

                if 'errors' in data:
                    logging.error("GraphQL fel: %s", data['errors'])
                    sys.exit("GraphQL-anrop returnerade fel")
                    
                receipts = data.get('data', {}).get('receiptsV2', {})
                receipt_list = receipts.get('list', [])
                total_receipts = receipts.get('total', 0)
                
                print(f"\nHittade {total_receipts} kvitton")
                
                # Spara hela kvittolistan som receipts.json
                receipts_json_path = os.path.join(json_dir, "receipts.json")
                with open(receipts_json_path, 'w', encoding='utf-8') as f:
                    json.dump(receipts, f, ensure_ascii=False, indent=2)
                print(f"Sparade kvittolista till {receipts_json_path}")
                
                # Iterera över varje kvitto
                print("\nHämtar detaljerad information och PDF för varje kvitto...")
                for receipt in receipt_list:
                    receipt_key = receipt.get('key')
                    if not receipt_key:
                        logging.warning("Kvitto saknar key, hoppar över")
                        continue
                    
                    print(f"\nBearbetar kvitto: {receipt_key}")
                    
                    # 1. Hämta detaljerad kvittoinformation via GraphQL
                    detail_query = """
                    query ReceiptDetails($key: String!) {
                      receiptV2(key: $key) {
                        key
                        content {
                          header {
                            totalPurchaseAmount
                            subAmounts
                            isoDate
                            formattedDate
                            text
                            labels {
                              type
                              text
                            }
                            logo {
                              publicUrl
                            }
                          }
                          footer {
                            text
                          }
                          items {
                            allItems {
                              text
                              items {
                                text
                                type
                                ... on ProductListItem {
                                  ...productFields
                                }
                                ... on GeneralDepositListItem {
                                  money {
                                    formatted
                                  }
                                  isRefund
                                  description
                                  text
                                }
                                ... on GeneralDiscountListItem {
                                  money {
                                    formatted
                                  }
                                  isRefund
                                  text
                                }
                                ... on GeneralModifierListItem {
                                  money {
                                    formatted
                                  }
                                  isRefund
                                  text
                                }
                              }
                            }
                            noBonusItems {
                              text
                              items {
                                type
                                ... on ProductListItem {
                                  ...productFields
                                }
                              }
                            }
                            returnedItems {
                              text
                              items {
                                type
                                ... on ProductReturnListItem {
                                  name
                                  money {
                                    formatted
                                  }
                                  quantityCost {
                                    formatted
                                  }
                                  deposits {
                                    description
                                    money {
                                      formatted
                                    }
                                    isRefund
                                  }
                                  costModifiers {
                                    description
                                    money {
                                      formatted
                                    }
                                    isRefund
                                  }
                                  connectedReceipt {
                                    receiptKey
                                    description
                                    isParentReceipt
                                  }
                                  identifiers
                                  text
                                }
                              }
                            }
                          }
                          storeInformation {
                            text
                            storeInformation {
                              property
                              value
                              subRows {
                                property
                                value
                              }
                            }
                          }
                          paymentInformation {
                            text
                            totals {
                              text
                              totals {
                                property
                                value
                                subRows {
                                  property
                                  value
                                }
                              }
                            }
                            paymentMethods {
                              text
                              methods {
                                type
                                information {
                                  property
                                  value
                                  subRows {
                                    property
                                    value
                                  }
                                }
                              }
                            }
                            customer {
                              text
                              customer {
                                property
                                value
                                subRows {
                                  property
                                  value
                                }
                              }
                            }
                            cashRegister {
                              text
                              cashRegister {
                                property
                                value
                                subRows {
                                  property
                                  value
                                }
                              }
                            }
                          }
                        }
                        campaigns {
                          image {
                            publicUrl
                          }
                          title
                          key
                          height
                          width
                          destinationUrl
                        }
                        sender {
                          name
                          key
                        }
                        attributes {
                          isUpdatedWithReturns
                        }
                      }
                    }

                    fragment productFields on ProductListItem {
                      name
                      money {
                        formatted
                      }
                      quantityCost {
                        formatted
                      }
                      deposits {
                        description
                        money {
                          formatted
                        }
                        isRefund
                      }
                      costModifiers {
                        description
                        money {
                          formatted
                        }
                        isRefund
                      }
                      identifiers
                      text
                    }
                    """
                    
                    detail_payload = {
                        "operationName": "ReceiptDetails",
                        "query": detail_query,
                        "variables": {
                            "key": receipt_key
                        }
                    }

                    # Debug information före GraphQL-anropet
                    logging.debug("GraphQL Headers:")
                    for header, value in headers.items():
                        logging.debug(f"  {header}: {value}")
                    logging.debug("GraphQL Payload:")
                    logging.debug(json.dumps(detail_payload, indent=2))
                    
                    # Hämta JSON-detaljer
                    detail_response = session.post(graphql_url, 
                                                json=detail_payload,
                                                headers=headers)
                    
                    if detail_response.status_code == 401:
                        logging.error("401 Unauthorized vid hämtning av kvittodetaljerna")
                        logging.error(f"Response headers: {dict(detail_response.headers)}")
                        logging.error(f"Response body: {detail_response.text}")
                        sys.exit("Autentiseringsfel - avslutar")
                    elif detail_response.status_code != 200:
                        logging.error(f"Fel vid hämtning av kvittodetaljerna för {receipt_key}: {detail_response.status_code}")
                        logging.error(f"Response headers: {dict(detail_response.headers)}")
                        logging.error(f"Response body: {detail_response.text}")
                        continue
                    
                    detail_data = detail_response.json()
                    if 'errors' in detail_data:
                        logging.error(f"GraphQL fel för kvitto {receipt_key}: {detail_data['errors']}")
                        continue
                    
                    receipt_details = detail_data.get('data', {}).get('receiptV2', {})
                    
                    # För kvitton:
                    # Skapa filnamn och mappar baserat på datum och butiksnamn
                    date = format_date(receipt_details.get('content', {}).get('header', {}).get('isoDate', 'unknown_date'))
                    store = receipt_details.get('sender', {}).get('name', 'unknown_store')
                    safe_store = clean_filename(store)
                    
                    # Skapa undermapp för butiken
                    store_dir = os.path.join(receipts_dir, safe_store)
                    store_json_dir = os.path.join(json_dir, safe_store)
                    os.makedirs(store_dir, exist_ok=True)
                    os.makedirs(store_json_dir, exist_ok=True)
                    
                    base_filename = f"{date}_{safe_store}_{receipt_key}"
                    
                    # Spara JSON i butiksspecifik json-mapp
                    json_filepath = os.path.join(store_json_dir, f"{base_filename}.json")
                    
                    # Spara PDF i butiksspecifik mapp
                    pdf_filepath = os.path.join(store_dir, f"{base_filename}.pdf")
                    
                    # 2. Spara JSON
                    with open(json_filepath, 'w', encoding='utf-8') as f:
                        json.dump(receipt_details, f, ensure_ascii=False, indent=2)
                    print(f"Sparade JSON: {base_filename}.json")
                    
                    # 3. Hämta och spara PDF direkt under Receipts
                    pdf_url = f"https://app.api.kivra.com/v1/user/{actor_key}/receipts/{receipt_key}"
                    pdf_headers = {
                        'Authorization': f'token {access_token}'
                    }
                    
                    logging.debug(f"PDF Headers: {pdf_headers}")
                    
                    pdf_response = session.get(pdf_url, headers=pdf_headers)
                    
                    if pdf_response.status_code == 200:
                        with open(pdf_filepath, 'wb') as f:
                            f.write(pdf_response.content)
                        print(f"Sparade PDF: {base_filename}.pdf")
                    else:
                        logging.error(f"Kunde inte hämta PDF för kvitto {receipt_key}. Status: {pdf_response.status_code}")
                        logging.error(f"PDF URL: {pdf_url}")
                        logging.error(f"PDF Headers: {pdf_headers}")
                        logging.error(f"PDF Response headers: {dict(pdf_response.headers)}")
                        logging.error(f"PDF Response body: {pdf_response.text}")
                        sys.exit(1)

            if FETCH_LETTERS:
                print("\nHämtar brev...")
                # Skapa Letters-mapp och undermappar under personnummermappen
                letters_dir = os.path.join(base_dir, "Letters")
                json_dir = os.path.join(letters_dir, "json")
                os.makedirs(letters_dir, exist_ok=True)
                os.makedirs(json_dir, exist_ok=True)
                
                # GraphQL query för att hämta brev
                letters_query = """
                query ContentList($filter: ContentListFilter!, $senderKey: String, $take: Int!, $after: ID) {
                  experimentalContents(
                    filter: $filter
                    senderKey: $senderKey
                    take: $take
                    after: $after
                  ) {
                    total
                    existsMore
                    list {
                      ...ContentBaseDetails
                    }
                  }
                }

                fragment ContentBaseDetails on IContentBaseDetails {
                  __typename
                  key
                  receivedAt
                  attributes {
                    isRead
                    isTrashed
                    isUpload
                  }
                  sender {
                    key
                    name
                    iconUrl
                  }
                  subject
                  accessInfo {
                    owner {
                      isMe
                      name
                    }
                  }
                }
                """

                # Iterera över varje brev med paginering
                all_letters = []
                after = None
                
                while True:
                    letters_payload = {
                        "operationName": "ContentList",
                        "query": letters_query,
                        "variables": {
                            "after": after,
                            "filter": "inbox",
                            "senderKey": None,
                            "take": 100  # Öka antalet per sida för färre anrop
                        }
                    }

                    letters_response = session.post(graphql_url, 
                                                 json=letters_payload,
                                                 headers=headers)

                    if letters_response.status_code != 200:
                        logging.error("Kunde inte hämta brevlista. Status: %d, Response: %s", 
                                    letters_response.status_code, letters_response.text)
                        sys.exit("Brev-hämtning misslyckades")

                    letters_data = letters_response.json()
                    
                    if 'errors' in letters_data:
                        logging.error("GraphQL fel: %s", letters_data['errors'])
                        sys.exit("GraphQL-anrop returnerade fel")

                    page_content = letters_data.get('data', {}).get('experimentalContents', {})
                    page_letters = page_content.get('list', [])
                    all_letters.extend(page_letters)
                    
                    exists_more = page_content.get('existsMore', False)
                    if not exists_more or not page_letters:
                        break
                        
                    # Använd sista brevets key som after för nästa sida
                    after = page_letters[-1]['key']
                    print(f"Hämtat {len(all_letters)} brev av {page_content.get('total', '?')}...")

                total_letters = len(all_letters)
                print(f"\nHittade totalt {total_letters} brev")

                # Spara hela brevlistan som letters.json
                letters_json_path = os.path.join(json_dir, "letters.json")
                with open(letters_json_path, 'w', encoding='utf-8') as f:
                    json.dump({"total": total_letters, "list": all_letters}, f, ensure_ascii=False, indent=2)
                print(f"Sparade brevlista till {letters_json_path}")
                
                # Iterera över varje brev för att hämta PDF och detaljer
                print("\nHämtar PDF och detaljer för varje brev...")
                for letter in all_letters:
                    letter_key = letter.get('key')
                    if not letter_key:
                        logging.warning("Brev saknar key, hoppar över")
                        continue
                    
                    print(f"\nBearbetar brev: {letter_key}")
                    
                    # Skapa filnamn och mappar baserat på datum och avsändare
                    date = format_date(letter.get('receivedAt', 'unknown_date'))
                    sender = letter.get('sender', {}).get('name', 'unknown_sender')
                    safe_sender = clean_filename(sender)
                    
                    # Skapa undermapp för avsändaren
                    sender_dir = os.path.join(letters_dir, safe_sender)
                    sender_json_dir = os.path.join(json_dir, safe_sender)
                    os.makedirs(sender_dir, exist_ok=True)
                    os.makedirs(sender_json_dir, exist_ok=True)
                    
                    base_filename = f"{date}_{safe_sender}_{letter_key}"
                    
                    # Spara JSON i avsändarspecifik json-mapp
                    json_filepath = os.path.join(sender_json_dir, f"{base_filename}.json")
                    
                    # Spara PDF i avsändarspecifik mapp
                    pdf_filepath = os.path.join(sender_dir, f"{base_filename}.pdf")
                    
                    # 1. Hämta detaljerad information
                    content_url = f"https://app.api.kivra.com/v1/content/{letter_key}"
                    content_headers = {
                        'Authorization': f'token {access_token}',
                        'Accept': 'application/json'
                    }
                    
                    content_response = session.get(content_url, headers=content_headers)
                    
                    if content_response.status_code == 200:
                        content_data = content_response.json()
                        # Kombinera metadata från listan med detaljerad information
                        letter_data = {**letter, "content": content_data}
                        
                        # Spara letter-metadata som JSON
                        with open(json_filepath, 'w', encoding='utf-8') as f:
                            json.dump(letter_data, f, ensure_ascii=False, indent=2)
                        print(f"Sparade JSON: {base_filename}.json")
                    else:
                        logging.error(f"Kunde inte hämta detaljer för brev {letter_key}. Status: {content_response.status_code}")
                        logging.error(f"Response: {content_response.text}")
                        continue
                    
                    # 2. Hämta och spara PDF
                    # Först hämta fil-ID från content-data
                    parts = content_data.get('parts', [])
                    if not parts:
                        logging.error(f"Brev {letter_key} har inga parts")
                        sys.exit("Hittade brev utan parts - avslutar")
                    
                    files_found = False
                    for part in parts:
                        content_type = part.get('content_type')
                        if content_type in ['text/plain', 'text/html']:
                            # Skippa text/plain och text/html parts
                            continue
                        elif content_type == 'application/pdf':
                            files_found = True
                            file_key = part.get('key')
                            if not file_key:
                                logging.warning(f"PDF part i brev {letter_key} saknar key")
                                continue
                                
                            pdf_url = f"https://app.api.kivra.com/v1/content/{letter_key}/file/{file_key}/raw"
                            pdf_headers = {
                                'Authorization': f'token {access_token}'
                            }
                            
                            pdf_response = session.get(pdf_url, headers=pdf_headers)
                            
                            if pdf_response.status_code == 200:
                                # Om det finns flera PDF-filer, lägg till part-index i filnamnet
                                pdf_filename = base_filename
                                if len([p for p in parts if p.get('content_type') == 'application/pdf']) > 1:
                                    part_index = parts.index(part)
                                    pdf_filename = f"{base_filename}_part{part_index}"
                                    
                                pdf_filepath = os.path.join(sender_dir, f"{pdf_filename}.pdf")
                                with open(pdf_filepath, 'wb') as f:
                                    f.write(pdf_response.content)
                                print(f"Sparade PDF: {pdf_filename}.pdf")
                            else:
                                logging.error(f"Kunde inte hämta PDF för brev {letter_key}, key {file_key}. Status: {pdf_response.status_code}")
                                logging.error(f"Response: {pdf_response.text}")
                                logging.error(f"URL: {pdf_url}")
                                logging.error(f"Headers: {pdf_headers}")
                                sys.exit(f"PDF-hämtning misslyckades med status {pdf_response.status_code}")
                        else:
                            logging.error(f"Okänd content-type i brev {letter_key}: {content_type}")
                            sys.exit(f"Hittade okänd content-type: {content_type}")
                    

                print("\nKlar med att spara alla brev!")

            print("\nKlar med att spara alla kvitton!")
            break  # Bryt polling-loopen

        elif poll_data.get('status') == 'pending':
            print(".", end="", flush=True)  # Visa progress
        else:
            logging.error("Fel vid polling. Status: %s, Response: %s", 
                         poll_data.get('status'), poll_data)
            sys.exit("BankID-autentisering misslyckades")

except Exception as e:
    logging.error("Fel vid parsning av svar: %s", str(e))
    sys.exit("Kunde inte tolka svar från Kivra")

# Ta bort temporär QR-kod fil
try:
    os.remove(temp_path)
except:
    pass






