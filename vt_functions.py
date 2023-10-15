import logging
import requests
import json
import csv
import time
import hashlib
import sqlite3
import datetime
from deepdiff import DeepDiff

logging.basicConfig(filename='vt_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_telegram_message(telegram_api_url,telegram_chat_id,message):
    try:
        requests.post(telegram_api_url, data={'chat_id': telegram_chat_id, 'text': message})
    except Exception as e:
        logging.error(f'Error sending Telegram message: {str(e)}')

def connect_to_database():
    # Connect to the database (or create it if it doesn't exist)
    logging.info(f"Connect to the database (or create it if it doesn't exist)")
    conn = sqlite3.connect('vt_analysis_results.db')
    logging.info(f"Connect to the database successful")
    return conn

### Cache table functions
def create_results_cache_table(conn):
    # Create a cache table, which will store previous scan results - results_cache_table
    logging.info(f"Create a cache table, which will store previous scan results - results_cache_table")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS results_cache_table
                    (id INTEGER PRIMARY KEY, record_type TEXT, value TEXT, analysis_results TEXT, full_results TEXT, last_analysis_date INTEGER, last_script_run INTEGER, vt_results_link TEXT)''')
    conn.commit()
    logging.info(f"results_cache_table have been created or already exist")


def update_results_cache_table(conn, record_type, value, analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link):
    # Update analysis result in table results_cache_table
    logging.info(f"Update analysis result in table results_cache_table")
    cursor = conn.cursor()
    # Check if record exists
    cursor.execute("SELECT * FROM results_cache_table WHERE record_type=? AND value=?", (record_type, value))
    vt_cache_table_record = cursor.fetchone()
    #print(f"vt_cache_table_record - {vt_cache_table_record}")
    logging.info(f"record type - {record_type}, value - {value}")
    if vt_cache_table_record:
        logging.info(f"record type - {record_type}, value - {value} - UPDATE results_cache_table")
        cursor.execute('''UPDATE results_cache_table SET analysis_results = ?, full_results = ?, last_analysis_date = ?, last_script_run = ? WHERE record_type = ? AND value = ?''',
                       (json.dumps(analysis_results), json.dumps(full_results), last_analysis_date, last_script_run, record_type, value))
    else:
        logging.info(f"record type - {record_type}, value - {value} - INSERT results_cache_table")
        cursor.execute("INSERT INTO results_cache_table (record_type, value, analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (record_type, value, json.dumps(analysis_results), json.dumps(full_results), last_analysis_date, last_script_run, vt_results_link))
    conn.commit()
    logging.info(f"Updated or Created")


### results table functions
def create_results_report_table(conn):
    # Create a report results table, which will be a source of csv or telegram bot report.
    logging.info(f"Create a results table, which will be a source of a report")
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS results_report_table;''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS results_report_table
                    (id INTEGER PRIMARY KEY, record_type TEXT, value TEXT, results_diff TEXT, last_analysis_date INTEGER, last_script_run INTEGER, status TEXT, vt_results_link TEXT)''')
    conn.commit()
    logging.info(f"Results table have been created successfully ")


def update_results_report_table(conn, record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link):
    # Update analysis result in table results_report_table
    logging.info(f"Update report results in table results_report_table, record_type - {record_type}, value - {value}")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO results_report_table (record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (record_type, value, results_diff,  last_analysis_date, last_script_run, status, vt_results_link))
    conn.commit()
    logging.info(f"Report results in table results_report_table have been updated successfully")


### update results tables
def update_results_tables(conn, existing_data, last_analysis_stats, record_type, value, last_analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link):
    logging.info(f"Update report results in table results_report_table, record_type - {record_type}, value - {value}")
    if existing_data:
        status = "update"
        results_diff = diff_new_old_results(existing_data, last_analysis_results)
        # print(type(results_diff))
        if results_diff and results_diff != "{}":
            # print(f"len reults_diff - {len(results_diff)}")
            update_results_report_table(conn, record_type, value, json.dumps(results_diff), last_analysis_date, last_script_run,
                                        status, vt_results_link)
        #print(f"existing_data - {existing_data}")
        logging.info(f"Updated results_report_table, record_type - {record_type}, value - {value}")
    else:
        status = "new"
        filtered_data = {}
        if last_analysis_stats['malicious'] != 0 or last_analysis_stats['suspicious'] != 0:
            for engine, analysis_results in last_analysis_results.items():
                if analysis_results['category'] in ['malicious', 'suspicious']:
                    filtered_data[engine] = analysis_results
            update_results_report_table(conn, record_type, value, json.dumps(filtered_data), last_analysis_date,
                                        last_script_run, status, vt_results_link)
        logging.info(f"Created in results_report_table, record_type - {record_type}, value - {value}")
    update_results_cache_table(conn, record_type, value, last_analysis_results, full_results, last_analysis_date,
                               last_script_run, vt_results_link)
    #logging.info(f"Updated record in update_results_cache_table, record_type - {record_type}, value - {value}")


def get_analysis_results_from_results_cache_table(conn, record_type, value):
    # Get analysis result from table results_cache_table
    cursor = conn.cursor()
    column_name = "analysis_results"
    cursor.execute("SELECT {} FROM results_cache_table WHERE record_type=? AND value=?".format(column_name), (record_type, value))
    existing_data = cursor.fetchone()
    logging.info(f"Got results from results_cache_table")
    return existing_data

def diff_new_old_results(existing_data, results):
    # Get difference between current detects and results from previous scan
    results_diff_deep = DeepDiff(json.loads(existing_data[0]), results)
    #print(f"results_diff_deep- {results_diff_deep}")
    results_diff = results_diff_deep.to_json()
    #print(f"results_diff- {results_diff}")
    logging.info(f"Got diff")
    return results_diff

def check_domain_vt(domain, headers, conn):
    logging.info(f"Get VT results for domain - {domain}")
    # Type of record to check
    record_type = "domain"
    # VT API link to check Domain info, return JSON
    vt_domain_link = f"https://www.virustotal.com/api/v3/domains/{domain}"
    # Current time of check
    date_epoch = int(time.time())
    response = requests.get(vt_domain_link, headers=headers)
    # If VT answers
    if response.status_code == 200:
        # The whole answer
        full_results = json.loads(response.text)

        #print(f"data - {full_results}")
        # Parts of answer
        attributes = full_results['data']['attributes']
        #print(f"attributes - {attributes}")

        last_analysis_stats = attributes['last_analysis_stats']
        #print(f"stats - {last_analysis_stats}")

        last_analysis_results = attributes['last_analysis_results']
        #print(f"results - {last_analysis_results}")

        last_analysis_date = attributes['last_analysis_date']
        #print(f"last_analysis_date - {last_analysis_date}")
        logging.info(f"last_analysis_date - {last_analysis_date}")

        # URL to add to the report.
        vt_link = f'https://www.virustotal.com/gui/domain/{domain}'

        existing_data = get_analysis_results_from_results_cache_table(conn, record_type, domain)

        update_results_tables(conn, existing_data, last_analysis_stats, record_type, domain, last_analysis_results,
                             full_results, last_analysis_date, date_epoch, vt_link)
        logging.info(f"Domain data received and updated - {domain}")
    else:
        print(f"Request detects from VT for {domain} failed with status code", response.status_code)
        logging.error(f"Request detects from VT for {domain} failed with status code", response.status_code)


def reanalyze_url_vt(url,headers):
    logging.info(f"Reanalyze for URL - {url}")
    # function send URL to reanalyze on VT
    url_sha256 = hashlib.sha256(url.encode())
    # hexidigest() returns the encoded data in hexadecimal format
    # print(url_sha256)
    #print('the hexadecimal equivalent of sha256 is : ', url_sha256.hexdigest())
    reanalyze_url = f"https://www.virustotal.com/api/v3/urls/{url_sha256.hexdigest()}/analyse"
    #print(reanalyze_url)
    response = requests.post(reanalyze_url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        #print(data)
        #print(data['data']['id'])
        logging.info(f"Reanalyze URL task id - {data['data']['id']}")
    else:
        print(f"Re-analysis request failed with status code", response.status_code)
        logging.error(f"Re-analysis request failed with status code", response.status_code)

    # end of function reanalyze URL

def check_domain_urls_vt(domain, headers, conn, analysis_age_acceptable):
    logging.info(f"Get VT results for domain related URLs - {domain}")
    # Type of record to check
    record_type = "url"
    # Current time of check
    #date_epoch = int(time.time())
    # VT API link to check Domain related URLs info, return JSON
    vt_domain_urls_link = f"https://www.virustotal.com/api/v3/domains/{domain}/urls"
    response = requests.get(vt_domain_urls_link, headers=headers)
    # If VT answers
    if response.status_code == 200:
        #print('response.text- ', response.text)
        full_results = json.loads(response.text)
        # data = response.text
        for url_element in full_results['data']:
            date_epoch = int(time.time())
            #print(date_epoch)

            #print('URL- ',url_element['context_attributes']['url'])
            #print('URL element- ', url_element)
            attributes = url_element['attributes']
            context_attributes = url_element['context_attributes']
            last_analysis_date = attributes['last_analysis_date']
            #print("last_analysis_date - ", last_analysis_date)
            url = context_attributes['url']
            #logging.info(f"Get VT results for domain related URLs - {domain}")

            analysis_age = date_epoch - last_analysis_date
            if analysis_age > analysis_age_acceptable:
                logging.info(f"URL will be rescanned, domain- {domain}, url - {url}, last_analysis_date - {last_analysis_date}, analysis_age - {analysis_age}")
                reanalyze_url_vt(url,headers)
                time.sleep(1)
            else:
                logging.info(f"URL will not be rescanned, domain- {domain}, url - {url}, last_analysis_date - {last_analysis_date}, analysis_age - {analysis_age}")
    else:
        print(f"Request related URL list for {domain} failed with status code", response.status_code)
        logging.error(f"Request related URL list for {domain} failed with status code", response.status_code)

    time.sleep(10)

    date_epoch = int(time.time())
    #print(date_epoch)
    response = requests.get(vt_domain_urls_link, headers=headers)
    if response.status_code == 200:
        # The whole answer
        full_results = json.loads(response.text)
        # data = response.text
        for url_element in full_results['data']:
            logging.info(f"Got URL Related to domain data- {domain}, url - {url}")

            #print('URL- ', url_element['context_attributes']['url'])
            #print('URL element- ', url_element)

            attributes = url_element['attributes']
            context_attributes = url_element['context_attributes']
            url = context_attributes['url']
            last_analysis_stats = attributes['last_analysis_stats']
            last_analysis_results = attributes['last_analysis_results']
            last_analysis_date = attributes['last_analysis_date']
            #print("last_analysis_date - ", last_analysis_date)

            url_sha256 = hashlib.sha256(url.encode())
            vt_link = f'https://www.virustotal.com/gui/url/{url_sha256.hexdigest()}'

            existing_data = get_analysis_results_from_results_cache_table(conn, record_type, url)

            update_results_tables(conn, existing_data, last_analysis_stats, record_type, url, last_analysis_results,
                                  url_element, last_analysis_date, date_epoch, vt_link)
            logging.info(f"URL Related to domain data updated in update_results_tables - {domain}, url - {url}")

    else:
        print(f"Request related URL list for {domain} failed with status code", response.status_code)
        logging.error(f"Request related URL list for {domain} failed with status code", response.status_code)


def get_results_from_results_report_table(conn,telegram_api_url,telegram_chat_id):
    #TODO
    #get results from result table and send them to JIRA or Telegram or Email?
    logging.info(f"Prepare report")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM results_report_table")
    rows = cursor.fetchall()
    #print(f"rows - {rows}")
    categories_of_interest = ['malicious', 'suspicious']

    for row in rows:
        print(f"row - {row}")
        record_number, record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link = row
        vt_results = json.loads(results_diff)
        print(f"vt_results - {vt_results}")
        if status == "new":
            #relevant_changes = []
            for vendor, analysis_results in vt_results.items():
                category = analysis_results.get('category')
                if category in categories_of_interest:
                    # Send message using your Telegram bot API here
                    #relevant_changes.append(f"New detection detected: {record_type}: {value}, vendor - {vendor}: {category}")

                    message = f"Warn! New resource have bad reputation! {record_type}: {value}, vendor: {vendor}, category: {category}, VT: {vt_results_link}"
                    # Send message logic here (assuming you have a function to send messages)
                    send_telegram_message(telegram_api_url,telegram_chat_id,message)
        elif status == "update":
            # Load the Python string into a Python dictionary
            vt_results_dic = json.loads(vt_results)
            relevant_changes = []
            for key, change in vt_results_dic.get('values_changed', {}).items():
                new_value = change.get('new_value')
                old_value = change.get('old_value')
                if old_value in ['undetected', 'clean', 'harmless'] and new_value in ['malicious', 'suspicious']:
                #if old_value in ['malicious', 'suspicious'] and new_value in ['undetected', 'clean', 'harmless']:
                    vendor = key.split("['")[1].split("']")[0]  # Extract vendor name from the key
                    relevant_changes.append(f"Warn! Reputation for resource changed to BAD! {record_type}: {value}, vendor - {vendor},   category: {old_value} -> {new_value}, VT: {vt_results_link}")
                elif old_value in ['malicious', 'suspicious'] and new_value in ['undetected', 'clean', 'harmless']:
                    vendor = key.split("['")[1].split("']")[0]  # Extract vendor name from the key
                    relevant_changes.append(f"Category for resource changed to GOOD. {record_type}: {value}, vendor - {vendor},   category: {old_value} -> {new_value}, VT: {vt_results_link}")
                #send_telegram_message(telegram_api_url, telegram_chat_id, relevant_changes)

            if relevant_changes:
                # Send message or perform the necessary action for relevant status changes
                for change in relevant_changes:
                    # Send message logic here
                    send_telegram_message(telegram_api_url,telegram_chat_id,change)


        # Now you can process each row as needed
        # For example, print the values or perform other operations
        #print(f"Record Type: {record_type}")
        #print(f"Value: {value}")
        #print(f"Results Diff: {results_diff}")
        #print(f"Last Analysis Date: {last_analysis_date}")
        #print(f"Last Script Run: {last_script_run}")
        #print(f"Status: {status}")
        #print(f"VT Results Link: {vt_results_link}")

