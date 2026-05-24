#!/usr/bin/env python3
"""
============================================================
BERMA Automatización e Ingeniería S.L.
Script de análisis de alertas Snort - Proyecto 3
============================================================
Descripción:
    Parsea los archivos CSV exportados desde pfSense/Snort,
    agrupa alertas por tipo de regla, genera visualizaciones
    y muestra un resumen ejecutivo en consola.

Formato CSV de pfSense Snort (sin cabecera):
    timestamp, iface_id, sid, rev, msg, proto,
    src_ip, src_port, dst_ip, dst_port, flow_id,
    classtype, priority, action, verdict

Uso:
    python analisis_snort_berma.py --lan alertas_lan.csv
    python analisis_snort_berma.py --lan lan.csv --opt1 opt1.csv
    python analisis_snort_berma.py --demo

Dependencias:
    pip install pandas matplotlib
============================================================
"""

import argparse
import os
import sys
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
from datetime import datetime, timedelta
import random

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────

OUTPUT_DIR = "graficas_berma"

# Columnas del CSV de pfSense Snort (sin cabecera)
COLUMNAS = [
    'timestamp', 'iface_id', 'sid', 'rev', 'msg', 'protocol',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flow_id',
    'classtype', 'priority', 'action', 'verdict'
]

# Nombre legible de cada regla personalizada BERMA
NOMBRES_REGLAS = {
    'BERMA-001': 'SSH Brute Force',
    'BERMA-002': 'Port Scan',
    'BERMA-003': 'HMI Web Access',
    'BERMA-004': 'Nikto Scanner',
    'BERMA-005': 'Modbus TCP',
    'BERMA-006': 'S7comm Siemens',
    'BERMA-007': 'Nmap Aggressive',
    'BERMA-008': 'ICMP Echo Request',
    'BERMA-009': 'ICMP Ping Sweep',
    'BERMA-TEST': 'Test ICMP',
}

# ─── CARGA ────────────────────────────────────────────────────────────────────

def cargar_alertas(filepath):
    """
    Carga el CSV de pfSense sin cabecera y asigna nombres de columna.
    pfSense exporta el log de Snort en texto plano separado por comas
    sin linea de cabecera. Las columnas se asignan segun el esquema
    conocido del formato interno de pfSense Snort.
    """
    if not os.path.exists(filepath):
        print(f"[ERROR] Archivo no encontrado: {filepath}")
        sys.exit(1)

    try:
        df = pd.read_csv(
            filepath,
            header=None,
            names=COLUMNAS,
            on_bad_lines='skip',
            encoding='utf-8',
            skipinitialspace=True
        )
        for col in df.select_dtypes(include='object').columns:
            df[col] = df[col].astype(str).str.strip()

        print(f"[OK] Cargado: {filepath}  ->  {len(df)} alertas")
        return df

    except Exception as e:
        print(f"[ERROR] No se pudo cargar el archivo: {e}")
        sys.exit(1)


# ─── PROCESAMIENTO ────────────────────────────────────────────────────────────

def parsear_timestamp(df):
    """
    Convierte la columna timestamp al tipo datetime de pandas.
    Formato pfSense: MM/DD/YY-HH:MM:SS.microsegundos
    Ejemplo:         05/15/26-12:01:06.436425
    """
    df = df.copy()
    df['ts'] = pd.to_datetime(
        df['timestamp'],
        format='%m/%d/%y-%H:%M:%S.%f',
        errors='coerce'
    )
    n_fallidos = df['ts'].isna().sum()
    if n_fallidos > 0:
        print(f"[AVISO] {n_fallidos} timestamps no parseables, se ignoraran en el timeline.")
    return df


def extraer_regla(msg):
    """
    Extrae el codigo de regla BERMA del campo mensaje de la alerta.
    Si el mensaje no contiene un codigo BERMA conocido, clasifica
    la alerta segun su contenido para diferenciar reglas de comunidad.

    Ejemplos:
      'BERMA-001 SSH Brute Force...'  ->  'BERMA-001'
      'ET SCAN Nmap...'               ->  'SCAN-COMUNIDAD'
    """
    if pd.isna(msg) or msg == 'nan':
        return 'DESCONOCIDA'

    msg_upper = str(msg).upper()

    for codigo in NOMBRES_REGLAS:
        if codigo in msg_upper:
            return codigo

    if 'SSH' in msg_upper or 'BRUTE' in msg_upper:
        return 'SSH-COMUNIDAD'
    elif 'SCAN' in msg_upper or 'NMAP' in msg_upper:
        return 'SCAN-COMUNIDAD'
    elif 'NIKTO' in msg_upper or 'WEB' in msg_upper:
        return 'WEB-COMUNIDAD'
    elif 'ICMP' in msg_upper or 'PING' in msg_upper:
        return 'ICMP-COMUNIDAD'
    elif 'MODBUS' in msg_upper or 'S7' in msg_upper:
        return 'OT-COMUNIDAD'
    else:
        return 'SNORT-COMUNIDAD'


def etiqueta(codigo):
    """Devuelve nombre legible para mostrar en graficas."""
    return NOMBRES_REGLAS.get(codigo, codigo.replace('-', ' '))


# ─── GRAFICAS ─────────────────────────────────────────────────────────────────

def grafica_por_tipo(df, interfaz, output_dir):
    """
    Barras verticales con conteo de alertas por tipo de regla.
    Rojo para reglas personalizadas BERMA, azul para comunidad.
    Permite identificar que ataques fueron mas frecuentes.
    """
    conteo = df['regla'].value_counts().sort_values(ascending=False)

    etiquetas = [f"{c}\n({etiqueta(c)})" for c in conteo.index]
    colores   = ['#c0392b' if 'BERMA' in str(c) else '#2980b9'
                 for c in conteo.index]

    fig, ax = plt.subplots(figsize=(max(10, len(conteo) * 1.8), 6))
    bars = ax.bar(range(len(conteo)), conteo.values,
                  color=colores, edgecolor='black', linewidth=0.6)

    for bar, val in zip(bars, conteo.values):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + max(conteo.values) * 0.015,
            str(val), ha='center', va='bottom',
            fontweight='bold', fontsize=9
        )

    ax.set_xticks(range(len(conteo)))
    ax.set_xticklabels(etiquetas, rotation=30, ha='right', fontsize=8)
    ax.set_title(
        f'Distribucion de Alertas Snort por Tipo de Regla\n'
        f'Interfaz: {interfaz}  -  BERMA Automatizacion e Ingenieria S.L.',
        fontsize=12, fontweight='bold', pad=15
    )
    ax.set_ylabel('Numero de Alertas', fontsize=10)
    ax.set_xlabel('Regla Snort', fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    leyenda = [
        mpatches.Patch(color='#c0392b', label='Reglas personalizadas BERMA'),
        mpatches.Patch(color='#2980b9', label='Reglas comunidad Snort GPLv2'),
    ]
    ax.legend(handles=leyenda, loc='upper right', fontsize=9)

    plt.tight_layout()
    ruta = os.path.join(output_dir, f'alertas_por_tipo_{interfaz}.png')
    plt.savefig(ruta, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[OK] Guardada: {ruta}")


def grafica_timeline(df, interfaz, output_dir):
    """
    Linea temporal de alertas agrupadas por minuto.
    Muestra los picos de actividad durante la simulacion de ataque.
    Permite correlacionar con los comandos ejecutados en Kali.
    """
    df_ts = df.dropna(subset=['ts'])
    if df_ts.empty:
        print(f"[AVISO] Sin timestamps validos en {interfaz}, omitiendo timeline.")
        return

    timeline = df_ts.set_index('ts').resample('1min').size()
    if timeline.empty or timeline.max() == 0:
        print(f"[AVISO] Sin datos temporales suficientes en {interfaz}.")
        return

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.fill_between(timeline.index, timeline.values,
                    alpha=0.35, color='#c0392b')
    ax.plot(timeline.index, timeline.values,
            color='#922b21', linewidth=2, marker='o', markersize=4)

    idx_max = timeline.idxmax()
    ax.annotate(
        f'Pico: {int(timeline.max())} alertas/min',
        xy=(idx_max, timeline.max()),
        xytext=(20, 15), textcoords='offset points',
        arrowprops=dict(arrowstyle='->', color='#922b21'),
        fontsize=9, color='#922b21', fontweight='bold'
    )

    ax.set_title(
        f'Linea Temporal de Ataques - Alertas por Minuto\n'
        f'Interfaz: {interfaz}  -  BERMA Automatizacion e Ingenieria S.L.',
        fontsize=12, fontweight='bold', pad=15
    )
    ax.set_xlabel('Tiempo (HH:MM)', fontsize=10)
    ax.set_ylabel('Alertas / Minuto', fontsize=10)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    ax.grid(alpha=0.3)
    plt.xticks(rotation=45)

    plt.tight_layout()
    ruta = os.path.join(output_dir, f'timeline_{interfaz}.png')
    plt.savefig(ruta, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[OK] Guardada: {ruta}")


def grafica_ips_atacantes(df, interfaz, output_dir):
    """
    Barras horizontales con las IPs origen mas activas.
    En el contexto de BERMA permite identificar el origen
    de los ataques y correlacionar con los accesos remotos
    documentados en el analisis Magerit (activos 2 y 9).
    """
    top = df['src_ip'].value_counts().head(10)
    if top.empty:
        print(f"[AVISO] Sin IPs origen en {interfaz}.")
        return

    fig, ax = plt.subplots(figsize=(10, max(4, len(top) * 0.75)))
    bars = ax.barh(range(len(top)), top.values,
                   color='#e67e22', edgecolor='black', linewidth=0.6)

    for bar, val in zip(bars, top.values):
        ax.text(
            bar.get_width() + max(top.values) * 0.01,
            bar.get_y() + bar.get_height() / 2.,
            str(val), ha='left', va='center',
            fontweight='bold', fontsize=9
        )

    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(top.index, fontsize=9)
    ax.invert_yaxis()
    ax.set_title(
        f'Top IPs Atacantes por Numero de Alertas\n'
        f'Interfaz: {interfaz}  -  BERMA Automatizacion e Ingenieria S.L.',
        fontsize=12, fontweight='bold', pad=15
    )
    ax.set_xlabel('Numero de Alertas', fontsize=10)
    ax.set_ylabel('IP Origen', fontsize=10)
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    ruta = os.path.join(output_dir, f'ips_atacantes_{interfaz}.png')
    plt.savefig(ruta, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[OK] Guardada: {ruta}")


# ─── RESUMEN CONSOLA ─────────────────────────────────────────────────────────

def imprimir_resumen(df, interfaz):
    """Resumen ejecutivo en consola."""
    linea = '-' * 60
    print(f"\n{linea}")
    print(f"  RESUMEN  -  {interfaz}")
    print(linea)
    print(f"  Total alertas          : {len(df):>6}")

    df_ts = df.dropna(subset=['ts'])
    if not df_ts.empty:
        duracion = df_ts['ts'].max() - df_ts['ts'].min()
        print(f"  Duracion del ataque    : {str(duracion).split('.')[0]:>6}")

    print(f"  Tipos de regla         : {df['regla'].nunique():>6}")
    print(f"\n  Top 5 reglas mas activas:")
    for regla, n in df['regla'].value_counts().head(5).items():
        nombre = etiqueta(regla)
        print(f"    {regla:<15} {nombre:<22} {n:>5} alertas")

    print(f"\n  Top 3 IPs atacantes:")
    for ip, n in df['src_ip'].value_counts().head(3).items():
        print(f"    {ip:<22} {n:>5} alertas")

    print(f"\n  Top 3 IPs victima:")
    for ip, n in df['dst_ip'].value_counts().head(3).items():
        print(f"    {ip:<22} {n:>5} alertas")

    print(linea)


# ─── PIPELINE ────────────────────────────────────────────────────────────────

def procesar_interfaz(filepath, nombre_interfaz, output_dir):
    """Pipeline completo: carga -> parsea -> extrae reglas -> graficas -> resumen."""
    df = cargar_alertas(filepath)
    df = parsear_timestamp(df)
    df['regla'] = df['msg'].apply(extraer_regla)

    grafica_por_tipo(df, nombre_interfaz, output_dir)
    grafica_timeline(df, nombre_interfaz, output_dir)
    grafica_ips_atacantes(df, nombre_interfaz, output_dir)
    imprimir_resumen(df, nombre_interfaz)

    return df


# ─── MODO DEMO ────────────────────────────────────────────────────────────────

def generar_demo(output_dir):
    """
    Genera un CSV de alertas simuladas representando los ataques
    del laboratorio BERMA: Nmap, Hydra, Nikto, pings ICMP.
    Util para probar el script sin los archivos reales de pfSense.
    El CSV generado tiene el mismo formato que el export de pfSense.
    """
    random.seed(42)
    inicio = datetime(2025, 5, 15, 10, 0, 0)
    ataques = [
        ('BERMA-008', 'BERMA-008 ICMP Echo Request - Reconocimiento activo', 60),
        ('BERMA-002', 'BERMA-002 Port Scan - Enumeracion red corporativa',    35),
        ('BERMA-007', 'BERMA-007 Nmap Aggressive Scan - Reconocimiento',       22),
        ('BERMA-001', 'BERMA-001 SSH Brute Force - Multiples intentos',        48),
        ('BERMA-004', 'BERMA-004 Web Scanner Nikto - Reconocimiento web',      15),
        ('BERMA-003', 'BERMA-003 HMI Web Access - Acceso interfaz Siemens',    10),
    ]

    filas = []
    t = inicio
    for i, (codigo, msg, n) in enumerate(ataques):
        for _ in range(n):
            t += timedelta(seconds=random.randint(1, 12))
            filas.append([
                t.strftime('%m/%d/%y-%H:%M:%S.000000'),
                1,
                f"900{i+1:04d}",
                1,
                msg,
                random.choice(['TCP', 'ICMP', 'UDP']),
                '192.168.100.100',
                random.randint(1024, 65535),
                '10.10.10.50',
                random.choice([22, 80, 443, 502]),
                random.randint(1000, 9999),
                'network-scan',
                2,
                'alert',
                'Allow',
            ])

    os.makedirs(output_dir, exist_ok=True)
    demo_path = os.path.join(output_dir, 'demo_alertas_berma.csv')
    pd.DataFrame(filas).to_csv(demo_path, index=False, header=False)
    print(f"[DEMO] CSV generado: {demo_path}  ({len(filas)} alertas)")
    return demo_path


# ─── ENTRADA PRINCIPAL ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Analisis alertas Snort - BERMA Automatizacion e Ingenieria S.L.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python analisis_snort_berma.py --lan alertas_lan.csv\n"
            "  python analisis_snort_berma.py --lan lan.csv --opt1 opt1.csv\n"
            "  python analisis_snort_berma.py --demo\n"
        )
    )
    parser.add_argument('--lan',  help='CSV de alertas interfaz LAN-BERMA-IDS')
    parser.add_argument('--opt1', help='CSV de alertas interfaz OPT1-ATACANTE-KALI')
    parser.add_argument('--demo', action='store_true',
                        help='Genera datos de prueba y ejecuta el analisis')
    args = parser.parse_args()

    if not args.lan and not args.opt1 and not args.demo:
        parser.print_help()
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"[INFO] Graficas en: {OUTPUT_DIR}/\n")

    if args.demo:
        demo_csv = generar_demo(OUTPUT_DIR)
        procesar_interfaz(demo_csv, 'LAN-BERMA-DEMO', OUTPUT_DIR)

    if args.lan:
        procesar_interfaz(args.lan, 'LAN-BERMA-IDS', OUTPUT_DIR)

    if args.opt1:
        procesar_interfaz(args.opt1, 'OPT1-ATACANTE-KALI', OUTPUT_DIR)

    print(f"\n[INFO] Analisis completado. Graficas en: {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
