import zipfile
import subprocess
import requests
import urllib
import io
import json
import base64
import os
import sys
import stat
from pathlib import Path


# Params used in the call to the baseline analysis.
# All the parameters set in the action are stored as environment variables with INPUT_ prefix
PARAM_KLA_BASEURL = os.environ["INPUT_KIUWANBASEURL"]
PARAM_KLA_APPNAME = os.environ["INPUT_PROJECT"]
PARAM_KLA_LABEL = os.environ["INPUT_LABEL"]
PARAM_KLA_USERNAME = os.environ["INPUT_USERID"]
PARAM_KLA_PASSWORD = os.environ["INPUT_PASSWORD"]
PARAM_KLA_SOURCEDIR = os.environ["INPUT_SOURCEPATH"]
PARAM_KLA_DATABASETYPE = os.environ["INPUT_DATABASETYPE"]
PARAM_KLA_ADVANCEDPARAMS = os.environ["INPUT_ADVANCEDPARAMS"]

KLA_URL = f"{PARAM_KLA_BASEURL}/pub/analyzer/KiuwanLocalAnalyzer.zip"
TMP_EXTRACTION_DIR = os.environ["WORKSPACE"] + "/kla"
KLA_EXE_DIR = f"{TMP_EXTRACTION_DIR}/KiuwanLocalAnalyzer/bin"

# Function to create the Kiuwan KLA line command.
# It is created with the minimum amount of parameters. Then the advanced parameters are passed in, the User is responsible for a good format
# Note the memory parameter has been already created properly
def get_kla_cmd(
    tmp_dir=TMP_EXTRACTION_DIR,
    appname=PARAM_KLA_APPNAME,
    label=PARAM_KLA_LABEL,
    sourcedir=PARAM_KLA_SOURCEDIR,
    user=PARAM_KLA_USERNAME,
    password=PARAM_KLA_PASSWORD,
    dbtype=PARAM_KLA_DATABASETYPE,
    advanced=PARAM_KLA_ADVANCEDPARAMS,
):
    prefix = f"{tmp_dir}/KiuwanLocalAnalyzer/bin/"
    agent = f"{prefix}agent.sh"
    os.chmod(agent, stat.S_IRWXU)

    kla_cmd = "{agent} -c -n {appname} -l {label} -s {sourcedir} --user {user} --pass {password} transactsql.parser.valid.list={dbtype} {advanced}".format()
    return kla_cmd


# Function to download and extract the Kiuwan Local Analyzer from kiuwan server
def download_and_extract_kla(tmp_dir=TMP_EXTRACTION_DIR, kla_url=KLA_URL):
    print("Downloading KLA zip from ", kla_url, " to [", tmp_dir, "]")
    resp = urllib.request.urlopen(kla_url)
    zipf = zipfile.ZipFile(io.BytesIO(resp.read()))
    Path(tmp_dir).mkdir(parents=True, exist_ok=True)
    zipf.extractall(tmp_dir)


# Parse the output of the analysis resutl to get the analysis code
def get_analysis_output_code(output_to_parse):
    return output_to_parse.split("Analysis created in Kiuwan with code:", 1)[1].split()[
        0
    ]


# Function to call the Kiuwan API to get the actual URL
def getBLAnalysisResultsURL(
    a_c,
    kla_user=PARAM_KLA_USERNAME,
    kla_password=PARAM_KLA_PASSWORD,
    advanced=PARAM_KLA_ADVANCEDPARAMS,
):
    apicall = "https://api.kiuwan.com"
    if not PARAM_KLA_BASEURL:
        apicall = f"{PARAM_KLA_BASEURL}/saas/rest/v1"

    apicall = apicall + "/apps/analysis/" + a_c
    print(f"Calling REST API [ {apicall} ]")

    kla_password = kla_password.replace("\\", "")
    authString = (
        base64.encodebytes((f"{kla_user}:{kla_password}").encode()).decode().strip()
    )

    if "domain-id" in advanced:
        posDomain = advanced.find("domain-id")
        value_domain_id = advanced[posDomain + 10 :]
        posWhitespace = value_domain_id.find(" ")
        if posWhitespace != -1:
            value_domain_id = value_domain_id[:posWhitespace]
        my_headers = {
            "Authorization": f"Basic {authString}",
            "X-KW-CORPORATE-DOMAIN-ID": value_domain_id,
        }
    else:
        my_headers = {"Authorization": f"Basic {authString}"}
    response = requests.get(url=apicall, headers=my_headers)
    url = json.loads(response.content)["analysisURL"]

    return url


# Function to excetute the actual Kiuwan Local Analyzer command line and get the resutls.
def execute_kla(cmd):
    print(f"Executing [ {cmd} ]")
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output_text = ""
    try:
        nextline = pipe.stdout.readline()
        while pipe.poll() == None:
            output_text = output_text + nextline.decode("utf-8")
            sys.stdout.write(nextline.decode("utf-8"))
            sys.stdout.flush()
            nextline = pipe.stdout.readline()
    except KeyboardInterrupt:
        return output_text, pipe.returncode
    return output_text, pipe.returncode


# Actual executing code after defining the functions
# Extract and download KLA from kiuwan.com (or from on-premise site)
download_and_extract_kla(tmp_dir=TMP_EXTRACTION_DIR)

# Build the KLA CLI command
kla_bl_cmd = get_kla_cmd(tmp_dir=TMP_EXTRACTION_DIR)

# Execute CLA KLI and set results as outputs
output, rc = execute_kla(kla_bl_cmd)
print(f"::set-output name=result::{rc}")
print(f"KLA return code: {rc}")
if rc == 0:
    analysis_code = get_analysis_output_code(output)
    print(f"Analysis code [ {analysis_code} ]")
    url_analysis = getBLAnalysisResultsURL(analysis_code)
    print("Analysis URL: ", url_analysis)
    print(f"::set-output name=analysisurl::{url_analysis}")
    print("::set-output name=message::Analysis successful.")
else:
    print(
        f"::set-output name=message::Error code {rc}, please go to:\n https://www.kiuwan.com/docs/display/K5/Analysis+Error+Code+Reference"
    )
