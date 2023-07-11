import csv
import io
import json
import requests
import sys
import uuid

COMMIT = '5ec393c527'    # NB (nphair): Not used.
MANUAL_ANALYSIS = 'https://raw.githubusercontent.com/nicholasphair/gdpr-analysis/main/plugin_meta/manual_analysis_meta.csv'
MEASUREMENT_ANALYSIS = 'https://raw.githubusercontent.com/nicholasphair/gdpr-analysis/main/plugin_meta/measurement_analysis_meta.csv'


def to_obj(line):
    body = json.dumps({'name': line.strip(), 'commit': COMMIT})
    return {'Id': str(uuid.uuid4()), 'MessageBody': body}


def to_json(infile, outfile):
    with open(outfile, 'w') as ouf:
        reader = csv.reader(infile)
        next(reader)
        data = [to_obj(row[5]) for row in reader]
        json.dump(data, ouf)


def download_inmem(url):
    response = requests.get(url)
    return io.TextIOWrapper(io.BytesIO(response.content))


outfile = sys.argv[1]
infile = download_inmem(MEASUREMENT_ANALYSIS)
to_json(infile, outfile)
