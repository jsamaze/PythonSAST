import sqlite3, sys
import subprocess, os, shutil

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

con = sqlite3.connect("CVEfixes.db")
con.row_factory = dict_factory

cur = con.cursor()

prevRepoUrl = "";
while True:
    print ("------------------")
    cur.execute(
    """
    SELECT cve.cve_id, cwe_classification.cwe_id, fixes.repo_url, commits.hash, repository.repo_name, repository.repo_language
    FROM cve, fixes, cwe_classification, commits, repository
    WHERE cve.cve_id = fixes.cve_id AND commits.hash = fixes.hash AND commits.repo_url = fixes.repo_url 
    AND cve.cve_id = cwe_classification.cve_id AND repository.repo_url = commits.repo_url and problematic =1 limit 1
    """)

    row = cur.fetchone()

    prevRepoName = "passawaylmao"
    if row is not None:
        # Do stuff
        print (row)
        repoNameShort = row['repo_url'].split("/")[-1]

        if os.path.isfile(f"D:/RA Script/2. bandit/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt"):
            shutil.move(f"D:/RA Script/2. bandit/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt"
                        , f"D:/RA Script/2. bandit/problematic/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt")
        
        cur.execute(
        f"""
        DELETE FROM cve WHERE cve_id = '{row['cve_id']}'
        """)

        con.commit()
            
    else:
        break