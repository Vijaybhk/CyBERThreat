from __future__ import annotations

import requests
import json
import time
import os

from datetime import datetime, timedelta

base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'


def scrape_cve(start_page=0, total_page=1000, page_size=1000, sleep_duration=3, start_date=None, end_date=None):
    """
    Scrap CVE using REST API.
    start_page: starting page to scrap
    total_page: max number of page to scrap
    page_size: number of CVE in one-page
    sleep_duration: sleep time in between each REST to avoid denial of service
    start_date: datetime object
    """

    if end_date is None:
        end_date = datetime.now()

    if start_date:
        # CVE modified date has the lowest granularity in minute.
        # Add one second to get the next CVE since last update.
        start_date = start_date.strftime('%Y-%m-%dT%H:%M:01')
        print('Start Date: {}'.format(start_date))
        end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S')
        print('End Date: {}'.format(end_date))

    cve_items = list()
    for page_no in range(start_page, total_page):
        for _ in range(5):
            try:
                print('Retrieving page: {}'.format(page_no + 1))
                url = '{}?startIndex={}&resultsPerPage={}'.format(base_url, page_no * page_size, page_size)
                if start_date:
                    url = '{}&lastModStartDate={}&lastModEndDate={}'.format(url, start_date, end_date)
                    # print(url)
                response = requests.get(url)
                response_json = json.loads(response.text)
                break

            except Exception as error:
                print(f'Something is wrong! Hit {type(error)}. Sleep for {sleep_duration} sec before retrying')
                time.sleep(sleep_duration)

        else:
            raise BaseException('Exhausted all attempts')

        cve_items += response_json['vulnerabilities']
        print('Scraped: {}'.format(len(cve_items)))
        if len(cve_items) == response_json['totalResults']:
            print('Completed scraping..')
            break
        time.sleep(sleep_duration)
    print('Total scraped: {}'.format(len(cve_items)))
    return cve_items


def main():

    file_path = "./data/cve.json"

    cve_id_list = []
    new_cve_list = []
    latest_time = None

    if os.path.isfile(file_path):
        with open(file_path, 'r') as fp:
            cve_list = json.load(fp)
        print('CVE downloaded before: {}'.format(len(cve_list)))

        for cve in cve_list:
            cve_id_list.append(cve['cve']['CVE_data_meta']['ID'])
            cve_last_modified_date = datetime.strptime(cve['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')
            if not latest_time:
                latest_time = cve_last_modified_date
            else:
                if latest_time < cve_last_modified_date:
                    latest_time = cve_last_modified_date
        print('Last updated time: {}'.format(latest_time))
    else:
        print('CVE has not been downloaded before')

    if latest_time is None:
        new_cve_list = scrape_cve(sleep_duration=2)
    else:
        today = datetime.now()
        start = latest_time

        while start < today:
            end = start + timedelta(days=2)
            new_cve = scrape_cve(sleep_duration=2, start_date=start, end_date=end)
            new_cve_list.extend(new_cve)
            start = end

        updated_cve = 0
        for new_cve in new_cve_list:
            new_cve_id = new_cve['cve']['id']
            if new_cve_id in cve_id_list:
                updated_cve += 1
                index = cve_id_list.index(new_cve_id)
                cve_list.pop(index)
                cve_id_list.pop(index)

        print('Total updated CVE: {}'.format(updated_cve))

        with open("./data/new_data.json", "w") as file:
            json.dump({"vulnerabilities": new_cve_list}, file)

        with open("./data/old_data.json", "w") as file:
            json.dump(cve_list, file)

    print('Total new CVE: {}'.format(len(new_cve_list)))

    return


if __name__ == "__main__":
    main()