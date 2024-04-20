import json
import os

import pandas as pd

from sklearn.model_selection import train_test_split


def main():

    data_dir = "./data"
    splits_dir = "./data/splits"

    for folder in data_dir, splits_dir:
        os.makedirs(folder, exist_ok=True)

    file_path = f"{data_dir}/old_data.json"

    with open(file_path, 'r') as fp:
        data = json.load(fp)
    print('Old CVEs: {}'.format(len(data)))

    cve_id = list()
    last_modified_date = list()
    published_date = list()
    attack_vector = list()
    attack_complexity = list()
    privileges_required = list()
    user_interaction = list()
    scope = list()
    confidentiality = list()
    integrity = list()
    availability = list()
    description = list()
    base_score = list()
    exploitability_score = list()
    impact_score = list()

    for idx in range(len(data)):
        try:
            if data[idx].get('impact') and data[idx]['impact'].get('baseMetricV3'):
                cve_id.append(data[idx]['cve']['CVE_data_meta']['ID'])
                attack_vector.append(data[idx]['impact']['baseMetricV3']['cvssV3']['attackVector'])
                attack_complexity.append(data[idx]['impact']['baseMetricV3']['cvssV3']['attackComplexity'])
                privileges_required.append(data[idx]['impact']['baseMetricV3']['cvssV3']['privilegesRequired'])
                user_interaction.append(data[idx]['impact']['baseMetricV3']['cvssV3']['userInteraction'])
                scope.append(data[idx]['impact']['baseMetricV3']['cvssV3']['scope'])
                confidentiality.append(data[idx]['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'])
                integrity.append(data[idx]['impact']['baseMetricV3']['cvssV3']['integrityImpact'])
                availability.append(data[idx]['impact']['baseMetricV3']['cvssV3']['availabilityImpact'])
                description.append(
                    ' '.join([text['value'] for text in data[idx]['cve']['description']['description_data']]))
                last_modified_date.append(data[idx]['lastModifiedDate'])
                published_date.append(data[idx]['publishedDate'])
                base_score.append(data[idx]['impact']['baseMetricV3']['cvssV3']['baseScore'])
                exploitability_score.append(data[idx]['impact']['baseMetricV3']['exploitabilityScore'])
                impact_score.append(data[idx]['impact']['baseMetricV3']['impactScore'])

        except KeyError:
            print('Key error at index: {}'.format(idx))
            break

    new_file_path = f"{data_dir}/new_data.json"
    with open(new_file_path, "r") as fp:
        new_data = json.load(fp)["vulnerabilities"]
    print('New CVEs: {}'.format(len(new_data)))

    for idx in range(len(new_data)):
        try:
            if new_data[idx]['cve'].get('metrics') and new_data[idx]['cve']['metrics'].get('cvssMetricV31'):
                cve_id.append(new_data[idx]['cve']['id'])
                metrics = new_data[idx]['cve']['metrics']['cvssMetricV31'][0]
                attack_vector.append(metrics['cvssData']['attackVector'])
                attack_complexity.append(metrics['cvssData']['attackComplexity'])
                privileges_required.append(metrics['cvssData']['privilegesRequired'])
                user_interaction.append(metrics['cvssData']['userInteraction'])
                scope.append(metrics['cvssData']['scope'])
                confidentiality.append(metrics['cvssData']['confidentialityImpact'])
                integrity.append(metrics['cvssData']['integrityImpact'])
                availability.append(metrics['cvssData']['availabilityImpact'])
                description.append(
                    text['value'] for text in new_data[idx]['cve']['descriptions'] if text["lang"] == "en"
                )
                last_modified_date.append(new_data[idx]['cve']['lastModified'])
                published_date.append(new_data[idx]['cve']['published'])
                base_score.append(metrics['cvssData']['baseScore'])
                exploitability_score.append(metrics['exploitabilityScore'])
                impact_score.append(metrics['impactScore'])

        except KeyError:
            print('Key error at index: {}'.format(idx))
            break

    df = pd.DataFrame(
        {
            'cve_id': cve_id,
            'attack_vector': attack_vector,
            'attack_complexity': attack_complexity,
            'privileges_required': privileges_required,
            'user_interaction': user_interaction,
            'scope': scope,
            'confidentiality': confidentiality,
            'integrity': integrity,
            'availability': availability,
            'description': description,
            'last_modified_date': last_modified_date,
            'published_date': published_date,
            'base_score': base_score,
            'exploitability_score': exploitability_score,
            'impact_score': impact_score,
        }
    )

    print("Total CVEs: {}".format(len(data)+len(new_data)))
    print('Total CVEs with CVSS base score: {}'.format(len(df)))
    print('Total percentage: {}'.format(len(df) / (len(data) + len(new_data))))

    df.to_csv(f"{data_dir}/cve.csv", sep=";")

    df_train, df_test = train_test_split(df, test_size=0.2, random_state=42)
    df_train.to_csv(f"{splits_dir}/train_data.csv", sep=";")
    df_test.to_csv(f"{splits_dir}/test_data.csv", sep=";")

    return


if __name__ == "__main__":
    main()