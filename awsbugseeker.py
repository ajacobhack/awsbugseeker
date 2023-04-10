import argparse
import subprocess
import threading

# Definimos los argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Escáner de vulnerabilidades para aplicaciones y entornos montados en AWS.')
parser.add_argument('--profile', type=str, help='perfil de AWS CLI')
parser.add_argument('--output', type=str, default='txt', choices=['txt', 'csv'], help='formato de salida de resultados')
args = parser.parse_args()

# Escaneamos las instancias EC2
def scan_ec2():
    subprocess.run(['aws', 'ec2', 'describe-instances'], check=True)

# Escaneamos los grupos de destino de balanceadores de carga
def scan_elb():
    subprocess.run(['aws', 'elbv2', 'describe-target-groups'], check=True)

# Escaneamos las instancias de bases de datos RDS
def scan_rds():
    subprocess.run(['aws', 'rds', 'describe-db-instances'], check=True)

# Escaneamos utilizando PACU
def scan_pacu():
    subprocess.run(['pacu', '-t', 'run', '-r', 'all'], check=True)

# Escaneamos utilizando Prowler
def scan_prowler():
    subprocess.run(['prowler', '-M', 'cis'], check=True)

# Creamos una lista de hilos para ejecutar los escaneos en paralelo
threads = []
threads.append(threading.Thread(target=scan_ec2))
threads.append(threading.Thread(target=scan_elb))
threads.append(threading.Thread(target=scan_rds))
threads.append(threading.Thread(target=scan_pacu))
threads.append(threading.Thread(target=scan_prowler))

# Ejecutamos el escaneo
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

# Imprimimos los resultados
print('\nResultados del escaneo:\n')
# Aquí se podrían procesar e imprimir los resultados de una forma más clara y legible, por ejemplo, utilizando colores para resaltar la gravedad de las vulnerabilidades encontradas

# Exportamos los resultados en un archivo
output_file = 'resultados_escaneo.' + args.output
with open(output_file, 'w') as f:
    # Aquí se podrían exportar los resultados en diferentes formatos, dependiendo de lo especificado en los argumentos
    f.write('Resultados del escaneo:\n')
    f.write('------------------------\n')
    f.write('\n')  # Aquí se podría escribir los resultados de forma organizada

print(f'Los resultados del escaneo se han exportado en el archivo "{output_file}".')
