# Traceroute + mapa HTML

Script en Python para ejecutar un traceroute con Scapy, consultar la geolocalización de cada IP con ip-api.com y dibujar la ruta en un mapa HTML con Folium.

## Requisitos

- Python 3.13+
- Permisos de red suficientes para enviar paquetes con Scapy
- En Windows, normalmente necesitas abrir la terminal como administrador y tener Npcap instalado para traceroute con paquetes crudos

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

```bash
python traceroute_map.py example.com --output mapa.html
```

Interfaz gráfica:

```bash
python traceroute_map.py --gui
```

Opciones útiles:

- `--max-hops 30`
- `--timeout 2.0`
- `--probes 1`

## Salida

El script genera un HTML con el mapa del trayecto de los saltos que pudieron geolocalizarse, una ruta animada y un panel lateral que resume el camino calculado con Dijkstra y el costo acumulado por salto.
