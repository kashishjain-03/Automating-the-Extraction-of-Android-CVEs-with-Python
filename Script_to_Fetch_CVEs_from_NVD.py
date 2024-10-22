##Automation Script to Fetch CVEs from NVD using NVDLib lib ##
import nvdlib as nv
import csv

cpeString= 'cpe:2.3:o:google:android:9.0'
api_key= 'api-key'
r = nv.searchCVE(cpeName = cpeString,key=api_key,delay=6)

# Find score of the CVSS scores
def findScore(cve, a, b,c):
    score =[]
    cve_score= getattr(eachCVE,a, None)
    cve_vector= getattr(eachCVE, b, None)
    cve_sev= getattr(eachCVE,c, None)
    score.append(cve_score)
    score.append(cve_vector)
    score.append(cve_sev)
    return score

with open('AndroidV9_CVE.csv', mode='w', newline='') as filewrite:
    fieldnames = ['CVE','Publised','Description', 'Url', 'Score:V3.1', 'Score:V3.0','Score:V2','CPES','Solutions','CWE']
    writer = csv.DictWriter(filewrite, fieldnames=fieldnames)
    writer.writeheader()
    for eachCVE in r:
        cve_id = eachCVE.id
        cve_published= eachCVE.published
        cve_descriptions= eachCVE.descriptions[0].value
        cve_url = eachCVE.url
        cve_score_v3_1= findScore(eachCVE, "v31score", "v31vector","v31severity")
        cve_score_v3_0= findScore(eachCVE, "v30score", "v30vector","v30severity")
        cve_score_v2= findScore(eachCVE, "v2score", "v2vector","v2severity")
        cve_cpes=[]
        for node in eachCVE.configurations:
            for cpe_m in node.nodes:
                  for crit in cpe_m.cpeMatch:
                      cve_cpes.append(crit.criteria)
        cve_hyperlinks=[]
        for hyperurl in eachCVE.references:
            cve_hyperlinks.append(hyperurl.url)
        cve_cwe= eachCVE.cwe[0].value
        writer.writerow({'CVE': cve_id,'Publised':cve_published,  'Description': cve_descriptions,'Url':cve_url, 'Score:V3.1':cve_score_v3_1, 'Score:V3.0':cve_score_v3_0,'Score:V2':cve_score_v2,'CPES':cve_cpes,'Solutions':cve_hyperlinks,'CWE':cve_cwe})