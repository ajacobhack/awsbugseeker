import argparse
import concurrent.futures
import subprocess

# Definimos los argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Escáner de vulnerabilidades para aplicaciones y entornos montados en AWS.')
parser.add_argument('--profile', type=str, help='perfil de AWS CLI')
parser.add_argument('--output', type=str, default='txt', choices=['txt', 'csv'], help='formato de salida de resultados')
args = parser.parse_args()

# Funciones de escaneo
def scan_ec2():
    return subprocess.run(['aws', 'ec2', 'describe-instances'], check=True, capture_output=True, text=True).stdout

def scan_elb():
    return subprocess.run(['aws', 'elbv2', 'describe-target-groups'], check=True, capture_output=True, text=True).stdout

def scan_rds():
    return subprocess.run(['aws', 'rds', 'describe-db-instances'], check=True, capture_output=True, text=True).stdout

def scan_pacu():
    return subprocess.run(['pacu', '-t', 'run', '-r', 'all'], check=True, capture_output=True, text=True).stdout

def scan_prowler():
    return subprocess.run(['prowler', '-M', 'cis'], check=True, capture_output=True, text=True).stdout

# Lista de tuplas con funciones de escaneo y argumentos
scan_functions = [
    (scan_ec2, ()),
    (scan_elb, ()),
    (scan_rds, ()),
    (scan_pacu, ()),
    (scan_prowler, ())
]

# Ejecutamos las funciones de escaneo en paralelo utilizando un ThreadPoolExecutor
with concurrent.futures.ThreadPoolExecutor() as executor:
    results = executor.map(lambda x: x[0](*x[1]), scan_functions)

# Procesamos los resultados y los almacenamos en un diccionario
scan_results = {}
for i, result in enumerate(results):
    scan_results[f'Escaneo {i+1}'] = result.splitlines()

# Escribimos los resultados en un archivo
output_file = f'resultados_escaneo.{args.output}'
with open(output_file, 'w') as f:
    for key, value in scan_results.items():
        f.write(f'{key}:\n')
        f.write('------------------------\n')
        for line in value:
            f.write(f'{line}\n')
        f.write('\n')

print(f'Los resultados del escaneo se han exportado en el archivo "{output_file}".')
