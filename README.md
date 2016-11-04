# pcap-cimd-elastisearch-exporter
Index CIMD packets from PCAP file(s) in Elasticsearch.

# Usage

```
usage: cimd-pcap-exporter.py [-h] --pcapfiles PCAPFILES [--filter FILTER]
                             --es-url ES_URL [--es-user ES_USER]
                             [--es-password ES_PASSWORD]

Index CIMD packets from PCAP file(s) in Elasticsearch.

optional arguments:
  -h, --help            show this help message and exit
  --pcapfiles PCAPFILES
                        Glob pattern matching PCAP files
  --filter FILTER       A display (wireshark) filter to apply on the cap while
                        reading it, should include only CIMD packets (default
                        is 'cimd')
  --es-url ES_URL       Elasticsearch address (with index and type, like
                        http://es.mydomain:9200/cimd/cimd)
  --es-user ES_USER     Elasticsearch user name
  --es-password ES_PASSWORD
                        Elasticsearch user password
```

# With Docker

From cloned repository (make sure script has Unix line endings) 

```
$ docker run --rm -it \
    -v $(realpath .)/:/app \
    -v /path-to-pcap-files:/pcap \
    jarekprzygodzki/pyshark \
    /app/cimd-pcap-exporter.py \
        --pcapfiles '/pcap/capture_0000*.cap' \
        --es-url http://es.local:9200/cimd/cimd \
        --es-user elastic --es-password changeme # credentials only if authorization is enabled in ES
```

To skip alive messages one can use `--filter` parameter

```
    /app/cimd-pcap-exporter.py \
        …
        --filter 'cimd && cimd.opcode != 40 and cimd.opcode != 90'
        …

```