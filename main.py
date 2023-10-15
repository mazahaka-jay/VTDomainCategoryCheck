import vt_functions
import time
import logging

# Logging config
logging.basicConfig(filename='vt_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Telegram configuration
TELEGRAM_BOT_TOKEN = 'TELEGRAM_BOT_TOKEN'
TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
TELEGRAM_CHAT_ID = 'TELEGRAM_CHAT_ID'


# Replace API_KEY with your VirusTotal API key
API_KEY = "API_KEY"

# how long can we wait before send ULR to recheck
analysis_age_acceptable = 43200

def main():
    logging.info('Script started.')
    conn = vt_functions.connect_to_database()
    vt_functions.create_results_cache_table(conn)
    vt_functions.create_results_report_table(conn)
    headers = {"x-apikey": API_KEY}

    # Replace domains_list with your list of domains
    domains_list = ["Domain.com"]
    for domain in domains_list:
        logging.info(f"Got diff")
        vt_functions.check_domain_vt(domain, headers, conn)
        time.sleep(1)
        vt_functions.check_domain_urls_vt(domain, headers, conn, analysis_age_acceptable)

        #check_domain_url_vt(domain, headers, conn)

    vt_functions.get_results_from_results_report_table(conn,TELEGRAM_API_URL,TELEGRAM_CHAT_ID)

    conn.close()
    logging.info('Script finished.')


if __name__ == "__main__":
    main()