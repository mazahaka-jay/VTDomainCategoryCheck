import requests
import json
import csv
import time
import hashlib
import sqlite3
import datetime
import vt_functions
from deepdiff import DeepDiff


# Replace API_KEY with your VirusTotal API key
API_KEY = "API_KEY"

# how long can we wait before send ULR to recheck
analysis_age_acceptable = 43200


def main():
    conn = connect_to_database()
    create_results_cache_table(conn)
    create_results_report_table(conn)
    headers = {"x-apikey": API_KEY}

    # Replace domains_list with your list of domains
    domains_list = ["academy.zfx.com","survey-smiles.com", "admin-academy.zfx.com", "zfx.com", "api.zfx.com", "admin.zfx.com"]
    #"academy.zfx.com", "admin-academy.zfx.com", "zfx.com", "api.zfx.com", "admin.zfx.com"
    for domain in domains_list:
        check_domain_vt(domain, headers, conn)
        time.sleep(1)
        check_domain_urls_vt(domain, headers, conn)

        #check_domain_url_vt(domain, headers, conn)

    get_results_from_results_report_table(conn)

    conn.close()


if __name__ == "__main__":
    main()