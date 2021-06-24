"""
    @author Adrian Gomez Martin
"""
import os.path, argparse, codecs, sys
from scapy.all import *
from colorama import Fore

"""
    Imprime distintos tipos de mensaje, el mensaje se recibe como parametro
"""
def imprime(msj, tipo = ''):
    msj = str(msj)
    if tipo == "err":
        simb = f"{Fore.RED}[!] ERROR:\t"
    elif tipo == "inf":
        simb = f"{Fore.CYAN}[+] INFO:\t"
    else:
        simb = f"{Fore.GREEN} >> "
    print(simb + msj)

"""
    Obtiene el numero magico del fichero y controla que sea válido
"""
def comprobar_numero_magico(file):   
    valido = False
    magicos_pcap = ["D4C3B2A1",# Little Endian LibPcap
                    "A1B2C3D4",# Big Endian LibPcap
                    "4D3CB2A1",# Little Endian  LibPcap (Resolucion nanosegundos)
                    "A1B23C4D"]# Big Endian  LibPcap (Resolucion nanosegundos)
    
    with open(file,"rb") as f:
        numero_magico = codecs.decode(codecs.encode(f.read(4),"hex"),"utf-8")
        numero_magico = numero_magico.upper()
        f.close()
    for magico in magicos_pcap:
        if magico == numero_magico:
            valido = True
    return valido

"""
    Comprueba la existencia del fichero y en caso de que exista lo envia como parametro
    a la funcion comprobar numero magico
"""
def comprobar_archivo(file):
    valido = False
    if os.path.isfile(file):
        valido = comprobar_numero_magico(file)    
    else:
        imprime(f"El archivo {file} no existe.","err")
        exit()
    return valido

"""
    Procesa el archivo PCAP filtrando por el puerto destino e IP que recibe como parametro
"""
def procesar_pcap(file, puerto_destino, ip_destino):
    pcap_reader = PcapReader(file)
    obtenido = False
    for packet in pcap_reader:
        try:
            if  packet[TCP].dport == int(puerto_destino) and packet.dst == ip_destino:  
                imprime(packet.show2(),"inf")
                dato = codecs.encode(str(packet[2]).strip().split("#")[0],"utf-8")
                if len(dato) != 0:
                    obtenido = True
        except IndexError:
            pass
    if obtenido:
        decodificar_raw_base64(dato)

"""
    Esta funcion decodifica el dato que recibe en base64
"""
def decodificar_raw_base64(dato):
    cadenas_base64 = str(dato).split("HTTP")[0].split("?")[1].split("&")
    imprime("DATOS OBTENIDOS","inf")
    for base64 in cadenas_base64:
        base64 = codecs.encode(base64,"utf-8")
        decodificado = codecs.decode(base64,"base64")
        imprime(str(decodificado))

"""
    Esta función gestiona los posibles errores al recibir argumentos
"""
def limpiar_argumentos(file, port, address):
    error = False
    salida = ""
    if file != None:
        salida += f"{file}|"
    else:
        imprime("El Script necesita un ARCHIVO PCAP para poder continuar.","err")
        error = True
    if port != None:
        salida += f"{port}|"
    else:
        imprime("El Script necesita un PUERTO DESTINO para poder continuar.","err")
        error = True
    if address != None:
        salida += f"{address}"
    else:        
        imprime("El Script necesita una DIRECCION DESTINO para poder continuar.","err")
        error = True
    if error:
        imprime(f"Uso: python3 {sys.argv[0]} -f FICHERO_PCAP.pcap -p PUERTO_DESTINO(Ejemplo: 80) -a IP_DESTINO", "inf")
        imprime("¿Desea obtener los resultados del ejercicio de manera automatizada? [S/n]","inf")
        a = input(f"{Fore.MAGENTA}==>\t")
        if len(a) == 0 or a[0].upper() == "S" :
            os.system(f"python3 {sys.argv[0]} -f australia.pcap -p 80 -a 49.50.8.230")
            exit()
        else:
            exit()
    return salida

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f","--file",help = "PCAP File", type = str)
    parser.add_argument("-p","--port",help = "Puerto destino a filtrar", type = int)
    parser.add_argument("-a","--address",help = "IP destino a filtrar", type = str)
    args = parser.parse_args()
    argumentos_validados = limpiar_argumentos(args.file, args.port, args.address).split("|")
    archivo_pcap = argumentos_validados[0]
    puerto_destino = argumentos_validados[1]
    ip_destino = argumentos_validados[2]
    if comprobar_archivo(archivo_pcap):
           procesar_pcap(archivo_pcap, puerto_destino, ip_destino)
    else:
        imprime(f"El archivo {archivo_pcap} NO ES UN PCAP.","err")

if __name__ == "__main__":
    main()