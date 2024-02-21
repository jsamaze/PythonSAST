import sqlite3
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
    AND cve.cve_id = cwe_classification.cve_id AND repository.repo_url = commits.repo_url limit 1
    """)

    row = cur.fetchone()

    prevRepoName = "passawaylmao"
    if row is not None:
        # Do stuff
        print (row)
        repoNameShort = row['repo_url'].split("/")[-1]
        try:
            if not os.path.isdir(f"/tmp/{repoNameShort}"):
                print(f"did not find repo {repoNameShort}")
                if os.path.isdir(f'/tmp/{prevRepoName}'):
                    shutil.rmtree(f'/tmp/{prevRepoName}')
                subprocess.run(["git", "clone", row["repo_url"]],check=True, cwd="/tmp")
            else:
                print(f"found repo {repoNameShort}")
            subprocess.run(["git", "fetch"], check=True,cwd=f"/tmp/{repoNameShort}")

            try:
                subprocess.run(["git", "checkout", f"{row['hash']}~"],check=True, cwd=f"/tmp/{repoNameShort}")
            except:
                subprocess.run(["git", "checkout", f"{row['hash']}^1"],check=True, cwd=f"/tmp/{repoNameShort}")
            
            try:
                with open(f"/mnt/d/RA Scrip/bearer/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt","w+") as f:
                    print("reached test", f)
                    subprocess.run(["/home/linuxbrew/.linuxbrew/bin/bearer", "scan",
                                    "--only-rule", "python_lang_logger,python_lang_weak_hash_md5,python_lang_weak_hash_sha1,python_lang_weak_password_encryption_md5,python_lang_weak_password_encryption_sha1",
                                    "--exit-code", "0" , repoNameShort , "--force"], cwd=f"/tmp", stdout=f, check=True)
            except subprocess.CalledProcessError as e:
                with open(f"/mnt/d/RA Scrip/bearer-all-rule/{row['cve_id']}+{repoNameShort}+{row['hash']}.txt","w+") as f:
                    print("reached test", f)
                    subprocess.run(["/home/linuxbrew/.linuxbrew/bin/bearer", "scan",
                                    # "--only-rule", "python_lang_logger,python_lang_weak_hash_md5,python_lang_weak_hash_sha1,python_lang_weak_password_encryption_md5,python_lang_weak_password_encryption_sha1",
                                    "--exit-code", "0" , repoNameShort , "--force"], cwd=f"/tmp", stdout=f, check=True)
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
            break
        except Exception as e:
            print("=====================")
            print(f"Fail to process {row['cve_id']}")
            print (e)
            print ("========================")
            break

        prevRepoName = repoNameShort

    else:
        break