import requests
import tomllib
import sys
import os
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')



url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers = {
    "accept": "application/json"
}

mitre_object = requests.get(url, headers=headers).json()
mitreMapped = {}

for object in mitre_object['objects']:
    tactics = []
    if object['type'] == 'attack-pattern':
        if 'external_references' in object:
            for reference in object['external_references']:
                if 'external_id' in reference:
                    if ((reference['external_id'].startswith("T"))):
                        if 'kill_chain_phases' in object:
                            for tactic in object['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        technique = reference['external_id']
                        name = object['name']
                        url = reference['url']

                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_object
                        else:
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': 'False'}
                            mitreMapped[technique] = filtered_object
                        
#print(mitreMapped['T1123']['url'])

for root, dirs, files in os.walk("Detection Rules"):
    for file in files:
        if file.endswith(".toml"):
            file = os.path.join(root, file)
            with open(file,"rb") as toml:
                alert = tomllib.load(toml)
                if alert['rule']['threat'['framework'] == 'MITRE ATT&CK']:
                    for x in alert['rule']['threat']:
                        print(x)