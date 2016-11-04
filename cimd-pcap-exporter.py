#!/usr/bin/python3

import argparse
import glob
import pyshark
import tqdm
import requests
import json

parser = argparse.ArgumentParser(description='Index CIMD packets from PCAP file(s) in Elasticsearch.')
parser.add_argument('--pcapfiles', 
                    help='Glob pattern matching PCAP files', required=True)
parser.add_argument('--filter', 
                    help='A display (wireshark) filter to apply on the cap while reading it, '\
                    'should include only CIMD packets (default is \'cimd\')', default='cimd')
parser.add_argument('--es-url', 
                    help='Elasticsearch address (with index and type, like http://es.mydomain:9200/cimd/cimd)', 
                    required=True)
parser.add_argument('--es-user', 
                    help='Elasticsearch user name')
parser.add_argument('--es-password', 
                    help='Elasticsearch user password')

args = parser.parse_args()

pcapfiles = glob.glob(args.pcapfiles)

def pkt_to_dict(pkt):
    # pkt must have field_names property
    return dict([(field, getattr(pkt, field)) for field in pkt.field_names if field is not ''])

def pkt_to_json(pkt):
    return json.dumps(pkt_to_dict(pkt))

def cimd_pkt_to_json(pkt):
    cimd_obj = pkt_to_dict(pkt.cimd)
    from datetime import datetime
    #  frame_info.time_epoch is time in seconds since the epoch as a floating point number
    time = datetime.utcfromtimestamp(float(pkt.frame_info.time_epoch))
    obj = { 'cimd' : cimd_obj, 'time': time.strftime('%Y-%m-%dT%H:%M:%S.%fZ') }
    return json.dumps(obj)

auth = (args.es_user, args.es_password) if args.es_user is not None and args.es_password is not None else None

pbar = tqdm.tqdm(pcapfiles)

for pcapfile in pbar:
    pbar.set_description("Processing %s" % pcapfile)
    capture =  pyshark.FileCapture(pcapfile, display_filter=args.filter)
    for pkt in tqdm.tqdm(capture):
        pkt_as_json = cimd_pkt_to_json(pkt)
        r = requests.post(args.es_url, data=pkt_as_json, auth = auth)
        assert r.status_code == 201
