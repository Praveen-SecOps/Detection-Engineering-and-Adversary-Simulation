import tomllib
import os
import sys

for root, dirs, files in os.walk("Detection Rules"):
    for file in files:
        if file.endswith(".toml"):
            file = os.path.join(root, file)
            with open(file,"rb") as toml:
                alert = tomllib.load(toml)

                required_field_map = {
                    'query' : ['description','name','risk_score','severity','type','query'],
                    'eql' : ['description','name','risk_score','severity','type','query','language'],
                    'threshold' : ['description','name','risk_score','severity','type','query','threshold'],
                }

                required_fields = required_field_map.get(alert['rule']['type'], [])
                if not required_fields:
                    print("Unknown rule type: " + alert['rule']['type'])
                    sys.exit(1)

                present_fields = [field for table in alert for field in alert[table]]
                missing_fields = [field for field in required_fields if field not in present_fields]

                if len(missing_fields) > 0:
                    print("Missing fields detected in " + file + "\n" + str(missing_fields))
                    sys.exit(1)
                else:
                    print("Validation passed for: " + file)