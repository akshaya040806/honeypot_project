#### Enhancing honeypot deception using AI generated network information

1) Create a file with everything in common in that file.
```bash
mkdir project
cd project
````

2) Start with tcpdump for packet capture
```bash
sudo tcpdump -i eth0 -w dataset.pcap
````

3) Install zeek (either by zeek itself or docker)

We want to process live network traffic directly from interfaces, building a custom pipeline with Zeek scripts, or work in offline or air-gapped environments.

We can try apt or docker

BY 'sudo apt' method

````bash
sudo apt update
sudo apt install zeek -y
zeek --version
````

If you want the latest version,

````bash
sudo apt update
sudo apt install cmake make gcc g++ flex bison libpcap-dev libssl-dev \
python3-dev swig zlib1g-dev libmaxminddb-dev libgeoip-dev libcurl4-openssl-dev git -y

git clone --recursive https://github.com/zeek/zeek
cd zeek

#Configuration
./configure
make -j$(nproc)
sudo make install

echo 'export PATH=/usr/local/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
````
If you want the docker version (for easy deployment)

````bash
sudo apt update
sudo apt install docker.io -y
sudo systemctl enable docker
sudo systemctl start docker

docker pull zeek/zeek

#Now run the .pcap we have
docker run --rm -v $PWD:/pcap zeek/zeek zeek -r /pcap/dataset.pcap
````

4) Take the dataset and apply zeek for .log files

Using sudo apt
````bash
zeek -r yourfile.pcap
````

Using docker
````bash
docker run --rm -v $PWD:/pcap zeek/zeek zeek -r /pcap/yourfile.pcap
````

5) Now, we have the .log files for conversion to JSON,

We can create a python script, which can convert the .log files to JSON for better analysis and feeding for ML.
````bash
import os
import json

def zeek_to_log(file):
    with open(file, 'r') as f:
        lines = f.readlines()

    field = []
    json_f = []
    for line in lines:
        if line.startswith('#field'):
            fields = line.strip().split('\t')[1:]
        elif not line.startswith('#') and fields:
            values = line.strip().split('\t')
            entry = dict(zip(fields, values))
            json_data.append(entry)
    return json_f

def convert_log_to_json(in_dir, out_dir):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    for filename in os.listdir(in_dir):
        if filename.endswith(".log"):
            log_path = os.path.join(in_dir, filename)
            json_out = zeek_to_log(log_path)

            json_file = filename.replace(".log", ".json")
            with open(os.path.join(out_dir, json_file), 'w') as jf:
                json.dump(json_out, jf, indent=2)
    print(f"JSON files saved in: {out_dir}")

def main():
    input_logs = os.path.expanduser("~/project")       
    output_json = "zeek_json_file"
    convert_all_logs_to_json(input_logs, output_json)

if __name__=="__main__":
    main()
````

This will convert the .log files into JSON files.

Now we can feed this to ML.

6) Create and train the model using CTGAN only and use scapy for packet crafting, and then inject using tcpreplay.

We can go for this option as it will give us realistic and accurate results.
We can use Virtual Environment, but if you don't want it like that it's fine, you can change it in the command.

Requirements:
````bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
python3 -m venv honeypot-env
source honeypot-env/bin/activate
pip install pandas scikit-learn ctgan scapy
````

Code for CTGAN
````bash
import pandas as pd
from ctgan import CTGANSynthesizer
from sklearn.preprocessing import LabelEncoder
import os

def process_zeek_json(path):
    df = pd.read_json(path, lines=True)

    # You can add more features if needed
    selected_columns = ['proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    df = df[selected_columns].dropna()

    cat_cols = ['proto', 'conn_state']
    encod = {}
    for col in cat_cols:
        encod[col] = LabelEncoder()
        df[col] = encod[col].fit_transform(df[col])
    return df, cate_cols, encod

def train_ctgan(df, cat_cols, epochs=300):
    ctg = CTGANSynthesizer(epochs=epochs)
    ctg.fit(df, cat_cols)
    return ctg

def generate_traffic(ctg, encod, cat_cols, samples=15):
    df_madeup = ctg.sample(samples)
    for col in cat_cols:
        df_madeup[col] = encod[col].inverse_transform(df_makeup[col].round().astype(int))
    return df_madeup

def main():
    input_json = "zeek_logs/GIVE_THE_DIRECTORY_INSIDE_YOU_WANT_IT_IN"
    out_csv = "output_for_tcp/synthetic.csv"

    os.makedirs("zeek_logs", exist_ok=True)
    os.makedirs("output_for_tcp", exist_ok=True)

    df, cat_cols, encod = preprocess_zeek_json(input_json)
    ctg = train_ctgan(df, cat_cols)
    synthetic_df = generate_traffic(ctg, encod, cat_cols, samples=20)
    synthetic_df.to_csv(out_csv, index=False)
    print(f"Synthetic traffic details saved to: {out_csv}")

if __name__ == "__main__":
    main()
````

for Packet Crafting
````bash
import pandas as pd
from scapy.all import IP, TCP, wrpcap, RandShort
import random
import os

def session(row, target_ip="192.168.1.100", target_port=80):
    if str(row['proto']).lower() != 'tcp':
        return []  
    packets = []

    # Fake source IP in subnet (realism)
    source_ip = f"192.168.1.{random.randint(1, 254)}"
    source_port = RandShort()
    ip_lay = IP(src=source_ip, dst=target_ip)
    tcp_seq = random.randint(1000, 4000)

    # Simulate TCP flow
    syn = ip_lay / TCP(sport=source_port, dport=target_port, flags='S', seq=tcp_seq)
    syn_ack = ip_lay / TCP(sport=source_port, dport=target_port, flags='SA', seq=tcp_seq + 1, ack=tcp_seq + 1)
    ack = ip_lay / TCP(sport=source_port, dport=target_port, flags='A', seq=tcp_seq + 1, ack=syn_ack.seq + 1)

    fake_page = random.randint(100, 999)
    payload = f"GET /page{fake_page}.html HTTP/1.1\r\nHost: honeypot\r\n\r\n"
    data_packets = ip_layer / TCP(sport=source_port, dport=target_port, flags='PA',seq=ack.seq, ack=ack.ack) / payload
    fin = ip_lay / TCP(sport=source_port, dport=target_port, flags='FA',seq=data_packets.seq + len(payload), ack=data_packets.ack)
    packets.extend([syn, syn_ack, ack, data_packet, fin])
    return packets

def main():
    csv_path = "data/synthetic.csv"         
    pcap_path = "output/traffic_for_pot.pcap"
    pot_ip = "192.168.1.100"                       

    flow_data = pd.read_csv(csv_input_path)
    tot_packets = []
    for _, row in flow_data.iterrows():
        packets = session(row, pot_ip)
        tot_packets.extend(packets)
    wrpcap(pcap_path, tot_packets)
    print(f"Saved {len(tot_packets)} packets to: {pcap_path}")

if __name__ == "__main__":
    main()
````

For injection (tcpreplay)

````bash
sudo tcpreplay -i eth0 output/traffic_for_pot.pcap
````

Network Emulation




