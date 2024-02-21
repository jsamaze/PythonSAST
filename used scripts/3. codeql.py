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
    AND cve.cve_id = cwe_classification.cve_id AND repository.repo_url = commits.repo_url and cve.probleatic=0 limit 1
    """)

    row = cur.fetchone()

    prevRepoName = "passawaylmao"
    if row is not None:
        # Do stuff
        print (row)
        repoNameShort = row['repo_url'].split("/")[-1]
        try:
            if not os.path.isdir(f"D:/tmp/{repoNameShort}"):
                print(f"did not find repo {repoNameShort}")
                if os.path.isdir(f'D:/tmp/{prevRepoName}'):
                    print(f"deleting {prevRepoName}")
                    shutil.rmtree(f'D:/tmp/{prevRepoName}')
                subprocess.run(["git", "clone", row["repo_url"]],check=True, cwd="D:/tmp")
            else:
                print(f"found repo {repoNameShort}")
            subprocess.run(["git", "fetch"], check=True,cwd=f"D:/tmp/{repoNameShort}")

            try:
                subprocess.run(["git", "checkout", f"{row['hash']}~"],check=True, cwd=f"D:/tmp/{repoNameShort}")
            except:
                subprocess.run(["git", "checkout", f"{row['hash']}^1"],check=True, cwd=f"D:/tmp/{repoNameShort}")
            
            print("reached test")
            #code
            if os.path.isdir(f"D:/tmp/{repoNameShort}/db"):
                shutil.rmtree(f"D:/tmp/{repoNameShort}/db")
            os.mkdir(f"D:/tmp/{repoNameShort}/db")
            subprocess.run(["D:/codeql-bundle-win64/codeql/codeql.exe", "database", "create", f"D:/tmp/{repoNameShort}/db", "--language=python"], cwd=f"D:/tmp/{repoNameShort}", check=True)
            subprocess.run(["D:/codeql-bundle-win64/codeql/codeql.exe", "database", "analyze", f"D:/tmp/{repoNameShort}/db", "--format=csv", 
                            f"--output=D:/RA script/3.codeql/{row['cve_id']}+{repoNameShort}+{row['hash']}.csv", "--verbose"],check=True)
            cur.execute(
            f"""
            DELETE FROM cve WHERE cve_id = '{row['cve_id']}'
            """)

            con.commit()
            
        except subprocess.CalledProcessError as e:
            print("=====================")
            print(f"Fail to process {row['cve_id']} - subprocess")
            print (e.output)
            print ("========================")
            cur.execute(
            f"""
            update cve set probleatic=1 where cve_id= '{row['cve_id']}'
            """)

            con.commit()

        except Exception as e:
            print("=====================")
            print(f"Fail to process {row['cve_id']}")
            print (e)
            print ("========================")
            cur.execute(
            f"""
            update cve set probleatic=1 where cve_id= '{row['cve_id']}'
            """)

            con.commit()
        finally:
            prevRepoName = repoNameShort

    else:
        break