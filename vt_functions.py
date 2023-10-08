def connect_to_database():
    # Connect to the database (or create it if it doesn't exist)
    conn = sqlite3.connect('vt_analysis_results.db')
    return conn

### Cache table functions
def create_results_cache_table(conn):
    # Create a cache table, which will store previous scan results - results_cache_table
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS results_cache_table
                    (id INTEGER PRIMARY KEY, record_type TEXT, value TEXT, analysis_results TEXT, full_results TEXT, last_analysis_date INTEGER, last_script_run INTEGER, vt_results_link TEXT)''')
    conn.commit()

def update_results_cache_table(conn, record_type, value, analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link):
    # Update analysis result in table results_cache_table
    cursor = conn.cursor()
    # Check if record exists
    cursor.execute("SELECT * FROM results_cache_table WHERE record_type=? AND value=?", (record_type, value))
    vt_cache_table_record = cursor.fetchone()
    print(f"vt_cache_table_record - {vt_cache_table_record}")
    if vt_cache_table_record:
        cursor.execute('''UPDATE results_cache_table SET analysis_results = ?, full_results = ?, last_analysis_date = ?, last_script_run = ? WHERE record_type = ? AND value = ?''',
                       (json.dumps(analysis_results), json.dumps(full_results), last_analysis_date, last_script_run, record_type, value))
    else:
        cursor.execute("INSERT INTO results_cache_table (record_type, value, analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (record_type, value, json.dumps(analysis_results), json.dumps(full_results), last_analysis_date, last_script_run, vt_results_link))
    conn.commit()

### results table functions
def create_results_report_table(conn):
    # Create a report results table, which will be a source of csv or telegram bot report.
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS results_report_table;''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS results_report_table
                    (id INTEGER PRIMARY KEY, record_type TEXT, value TEXT, results_diff TEXT, last_analysis_date INTEGER, last_script_run INTEGER, status TEXT, vt_results_link TEXT)''')
    conn.commit()

def update_results_report_table(conn, record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link):
    # Update analysis result in table results_report_table
    cursor = conn.cursor()
    cursor.execute("INSERT INTO results_report_table (record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (record_type, value, results_diff,  last_analysis_date, last_script_run, status, vt_results_link))
    conn.commit()

### update results tables
def update_results_tables(conn, existing_data, last_analysis_stats, record_type, value, last_analysis_results, full_results, last_analysis_date, last_script_run, vt_results_link):
    if existing_data:
        status = "update"
        results_diff = diff_new_old_results(existing_data, last_analysis_results)
        # print(type(results_diff))
        if results_diff and results_diff != "{}":
            # print(f"len reults_diff - {len(results_diff)}")
            update_results_report_table(conn, record_type, value, json.dumps(results_diff), last_analysis_date, last_script_run,
                                        status, vt_results_link)
        print(f"existing_data - {existing_data}")
    else:
        status = "new"
        filtered_data = {}
        if last_analysis_stats['malicious'] != 0 or last_analysis_stats['suspicious'] != 0 or last_analysis_stats[
            'undetected'] != 0:
            for engine, analysis_results in last_analysis_results.items():
                if analysis_results['category'] in ['malicious', 'suspicious', 'undetected']:
                    filtered_data[engine] = analysis_results
            update_results_report_table(conn, record_type, value, json.dumps(filtered_data), last_analysis_date,
                                        last_script_run, status, vt_results_link)
    update_results_cache_table(conn, record_type, value, last_analysis_results, full_results, last_analysis_date,
                               last_script_run, vt_results_link)

def get_analysis_results_from_results_cache_table(conn, record_type, value):
    # Get analysis result from table results_cache_table
    cursor = conn.cursor()
    column_name = "analysis_results"
    cursor.execute("SELECT {} FROM results_cache_table WHERE record_type=? AND value=?".format(column_name), (record_type, value))
    existing_data = cursor.fetchone()
    return existing_data

def diff_new_old_results(existing_data, results):
    # Get difference between current detects and results from previous scan
    results_diff_deep = DeepDiff(json.loads(existing_data[0]), results)
    #print(f"results_diff_deep- {results_diff_deep}")
    results_diff = results_diff_deep.to_json()
    #print(f"results_diff- {results_diff}")
    return results_diff

def check_domain_vt(domain, headers, conn):

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

        print(f"data - {full_results}")
        # Parts of answer
        attributes = full_results['data']['attributes']
        print(f"attributes - {attributes}")

        last_analysis_stats = attributes['last_analysis_stats']
        print(f"stats - {last_analysis_stats}")

        last_analysis_results = attributes['last_analysis_results']
        print(f"results - {last_analysis_results}")

        last_analysis_date = attributes['last_analysis_date']
        print(f"last_analysis_date - {last_analysis_date}")


        # URL to add to the report.
        vt_link = f'https://www.virustotal.com/gui/domain/{domain}'

        existing_data = get_analysis_results_from_results_cache_table(conn, record_type, domain)

        update_results_tables(conn, existing_data, last_analysis_stats, record_type, domain, last_analysis_results,
                             full_results, last_analysis_date, date_epoch, vt_link)

    else:
        print(f"Request detects from VT for {domain} failed with status code", response.status_code)


def reanalyze_url_vt(url,headers):
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
        print(data)
        print(data['data']['id'])
    else:
        print(f"Re-analysis request failed with status code", response.status_code)
    # end of function reanalyze URL




def check_domain_urls_vt(domain, headers, conn):
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
            print(date_epoch)

            print('URL- ',url_element['context_attributes']['url'])
            print('URL element- ', url_element)
            attributes = url_element['attributes']
            context_attributes = url_element['context_attributes']
            last_analysis_date = attributes['last_analysis_date']
            print("last_analysis_date - ", last_analysis_date)
            url = context_attributes['url']

            analysis_age = date_epoch - last_analysis_date
            if analysis_age > analysis_age_acceptable:
                reanalyze_url_vt(url,headers)
                time.sleep(1)

    time.sleep(10)

    date_epoch = int(time.time())
    print(date_epoch)
    response = requests.get(vt_domain_urls_link, headers=headers)
    if response.status_code == 200:
        # The whole answer
        full_results = json.loads(response.text)
        # data = response.text
        for url_element in full_results['data']:

            print('URL- ', url_element['context_attributes']['url'])
            print('URL element- ', url_element)

            attributes = url_element['attributes']
            context_attributes = url_element['context_attributes']
            url = context_attributes['url']
            last_analysis_stats = attributes['last_analysis_stats']
            last_analysis_results = attributes['last_analysis_results']
            last_analysis_date = attributes['last_analysis_date']
            print("last_analysis_date - ", last_analysis_date)

            url_sha256 = hashlib.sha256(url.encode())
            vt_link = f'https://www.virustotal.com/gui/url/{url_sha256.hexdigest()}'

            existing_data = get_analysis_results_from_results_cache_table(conn, record_type, url)

            update_results_tables(conn, existing_data, last_analysis_stats, record_type, url, last_analysis_results,
                                  url_element, last_analysis_date, date_epoch, vt_link)

    else:
        print(f"Request related URL list for {domain} failed with status code", response.status_code)



def get_results_from_results_report_table(conn):
    #TODO
    #get results from result table and send them to JIRA or Telegram or Email?
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM results_report_table")
    rows = cursor.fetchall()
    print(f"rows - {rows}")
    for row in rows:
        print(f"row - {row}")
        record_number, record_type, value, results_diff, last_analysis_date, last_script_run, status, vt_results_link = row

        # Now you can process each row as needed
        # For example, print the values or perform other operations
        print(f"Record Type: {record_type}")
        print(f"Value: {value}")
        print(f"Results Diff: {results_diff}")
        print(f"Last Analysis Date: {last_analysis_date}")
        print(f"Last Script Run: {last_script_run}")
        print(f"Status: {status}")
        print(f"VT Results Link: {vt_results_link}")