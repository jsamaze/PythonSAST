import sqlite3
import json
import os

JSON_OUTPUT = "./6.graudit/problem.json"


def dict_factory(cursor, row):
    fields = [column[0] for column in cursor.description]
    return {key: value for key, value in zip(fields, row)}

con = sqlite3.connect("CVEfixes.db")
con.row_factory = dict_factory

data = list(con.execute("""
                        SELECT cve.cve_id, cwe_classification.cwe_id, fixes.repo_url, commits.hash, repository.repo_name, repository.repo_language
                        FROM cve, fixes, cwe_classification, commits, repository
                        WHERE cve.cve_id = fixes.cve_id AND commits.hash = fixes.hash AND commits.repo_url = fixes.repo_url 
                            AND cve.cve_id = cwe_classification.cve_id AND repository.repo_url = commits.repo_url               
                        """))

json_data = json.dumps(data)
# json_data = json_data.replace("}, {", "},\n{")

if os.path.exists(JSON_OUTPUT):
  os.remove(JSON_OUTPUT)
  print("Replacing the old file")
else:
  print("Creating a new file")
with open(JSON_OUTPUT,'w') as file:
    file.write(json_data)





