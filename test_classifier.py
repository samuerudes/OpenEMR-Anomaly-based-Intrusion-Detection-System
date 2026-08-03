import pandas as pd
import sys, os
sys.path.insert(0, os.path.expanduser('~/ids_system'))
from detector import _classify_attack_type

df = pd.read_csv(os.path.expanduser('~/captures/combined_dataset.csv'))
attack = df[df['label'] == 'attack'].copy()

attack['predicted_type'] = attack.apply(
    lambda r: _classify_attack_type({
        'packets_per_second': r['packets_per_second'],
        'bytes_per_second':   r['bytes_per_second'],
        'total_bytes':        r['total_bytes'],
        'total_packets':      r['total_packets'],
        'mean_packet_size':   r['mean_packet_size'],
        'flow_duration':      r['flow_duration'],
        'dst_port':           r.get('dst_port', 0),
        'protocol':           r.get('protocol', 'TCP'),
    }), axis=1
)

print("=== PREDICTED ATTACK TYPE DISTRIBUTION ===")
print(attack['predicted_type'].value_counts())
print(f"\nTotal attack flows: {len(attack)}")
print(f"'Other Anomaly' %: {(attack['predicted_type']=='Other Anomaly').mean()*100:.1f}%")
