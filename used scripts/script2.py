import sqlite3, sys
import subprocess, os, shutil

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# def onerror(func, path, exc_info):
#     """
#     Error handler for ``shutil.rmtree``.

#     If the error is due to an access error (read only file)
#     it attempts to add write permission and then retries.

#     If the error is for another reason it re-raises the error.
    
#     Usage : ``shutil.rmtree(path, onerror=onerror)``
#     """
#     import stat
#     # Is the error an access error?
#     if not os.access(path, os.W_OK):
#         os.chmod(path, stat.S_IWUSR)
#         func(path)
#     else:
#         raise

con = sqlite3.connect("CVEfixes1.db")
con.row_factory = dict_factory

cur = con.cursor()

prevRepoUrl = "";
prevRepoName = "passawaylmao"

while True:
    print ("------------------")
    cur.execute(
    """
    SELECT cve.cve_id, cwe_classification.cwe_id, fixes.repo_url, commits.hash, repository.repo_name, repository.repo_language
    FROM cve, fixes, cwe_classification, commits, repository
    WHERE cve.cve_id = fixes.cve_id AND commits.hash = fixes.hash AND commits.repo_url = fixes.repo_url 
    AND cve.cve_id = cwe_classification.cve_id AND repository.repo_url = commits.repo_url and cve.problematic=0
     limit 1
    """)

    row = cur.fetchone()

    if row is not None:
        # Do stuff
        print (row)
        print (prevRepoName)
        repoNameShort = row['repo_url'].split("/")[-1]
        try:
            if not os.path.isdir(f"/tmp/{repoNameShort}"):
                print(f"did not find repo {repoNameShort}")
                if os.path.isdir(f'/tmp/{prevRepoName}'):
                    print(f"deleting {prevRepoName}")
                    shutil.rmtree(f'/tmp/{prevRepoName}')
                subprocess.run(["git", "clone", row["repo_url"]],check=True, cwd="/tmp")
            else:
                
                print(f"found repo {repoNameShort}")
            subprocess.run(["git", "fetch"], check=True,cwd=f"/tmp/{repoNameShort}")
            subprocess.run(["git", "config", "--global", "--add", "safe.directory", f"/tmp/{repoNameShort}"],check=True)

            try:
                subprocess.run(["git", "checkout", f"{row['hash']}~"],check=True, cwd=f"/tmp/{repoNameShort}")
            except:
                subprocess.run(["git", "checkout", f"{row['hash']}^1"],check=True, cwd=f"/tmp/{repoNameShort}")
            
            print("reached test")

            # with open(f"/mnt/c/Users/User/OneDrive - Singapore Management University/University Subjects/Y2T2/RA/Python-SAST-Test/6.graudit/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt","w+") as f:
                #code
            subprocess.run(["/home/linuxbrew/.linuxbrew/bin/semgrep", "scan", "--text", "-o", f"/home/joshuasumarlin/semgrep/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt"],cwd=f"/tmp/{repoNameShort}" ,check=True)

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
            update cve set problematic=1 where cve_id= '{row['cve_id']}'
            """)

            con.commit()

        except Exception as e:
            print("=====================")
            print(f"Fail to process {row['cve_id']}")
            print (e)
            print ("========================")
            cur.execute(
            f"""
            update cve set problematic=1 where cve_id= '{row['cve_id']}'
            """)

            con.commit()
        finally:
            print("reached finally")
            prevRepoName = repoNameShort

    else:
        break