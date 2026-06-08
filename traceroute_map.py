from __future__ import annotations

import argparse
import math
import socket
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from heapq import heappop, heappush
from typing import Iterable

import folium
import requests
from branca.element import Element
from folium.features import DivIcon
from folium.plugins import AntPath
from scapy.all import IP, UDP, sr1
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


@dataclass(frozen=True)
class Hop:
    ttl: int
    ip: str | None
    rtt_ms: float | None
    geolocation: dict | None


@dataclass(frozen=True)
class RouteStep:
    order: int
    hop: Hop
    lat: float
    lon: float
    segment_km: float
    cumulative_km: float


class GeoLocator:
    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()
        self._cache: dict[str, dict | None] = {}

    def lookup(self, ip: str) -> dict | None:
        if ip in self._cache:
            return self._cache[ip]

        url = f"http://ip-api.com/json/{ip}"
        params = {
            "fields": "status,message,country,regionName,city,lat,lon,query,isp,org,as,zip,mobile,proxy,hosting",
        }
        try:
            response = self._session.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException:
            self._cache[ip] = None
            return None
        except ValueError:
            self._cache[ip] = None
            return None

        if data.get("status") != "success":
            self._cache[ip] = None
            return None

        self._cache[ip] = data
        return data


def resolve_target(target: str) -> str:
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        resolved = socket.gethostbyname(target)
        return resolved


def run_traceroute(destination: str, max_hops: int, timeout: float, probes_per_hop: int) -> list[Hop]:
    hops: list[Hop] = []
    for ttl in range(1, max_hops + 1):
        best_response_ip: str | None = None
        best_rtt_ms: float | None = None

        for _ in range(probes_per_hop):
            packet = IP(dst=destination, ttl=ttl) / UDP(dport=33434)
            reply = sr1(packet, timeout=timeout, verbose=0)
            if reply is None:
                continue

            response_ip = reply.src
            sent_time = getattr(packet, "sent_time", None)
            rtt_ms = float(reply.time - sent_time) * 1000 if sent_time is not None else None
            if best_response_ip is None:
                best_response_ip = response_ip
                best_rtt_ms = rtt_ms

            if response_ip == destination:
                hops.append(Hop(ttl=ttl, ip=response_ip, rtt_ms=best_rtt_ms, geolocation=None))
                return hops

        hops.append(Hop(ttl=ttl, ip=best_response_ip, rtt_ms=best_rtt_ms, geolocation=None))

    return hops


def enrich_hops_with_geo(hops: list[Hop], geolocator: GeoLocator) -> list[Hop]:
    enriched: list[Hop] = []
    for hop in hops:
        if hop.ip is None:
            enriched.append(hop)
            continue
        geolocation = geolocator.lookup(hop.ip)
        enriched.append(Hop(ttl=hop.ttl, ip=hop.ip, rtt_ms=hop.rtt_ms, geolocation=geolocation))
    return enriched


def valid_geo_points(hops: Iterable[Hop]) -> list[tuple[Hop, float, float]]:
    points: list[tuple[Hop, float, float]] = []
    for hop in hops:
        if not hop.geolocation:
            continue
        lat = hop.geolocation.get("lat")
        lon = hop.geolocation.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            points.append((hop, float(lat), float(lon)))
    return points


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    return 2 * radius_km * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def build_dijkstra_route(hops: list[Hop]) -> tuple[list[RouteStep], float]:
    points = valid_geo_points(hops)
    if not points:
        return [], 0.0

    count = len(points)
    adjacency: dict[int, list[tuple[int, float]]] = {index: [] for index in range(count)}
    for index in range(count - 1):
        _, lat1, lon1 = points[index]
        _, lat2, lon2 = points[index + 1]
        segment_km = haversine_km(lat1, lon1, lat2, lon2)
        adjacency[index].append((index + 1, segment_km))

    distances = {0: 0.0}
    previous: dict[int, int] = {}
    queue: list[tuple[float, int]] = [(0.0, 0)]

    while queue:
        current_cost, node = heappop(queue)
        if current_cost > distances.get(node, float("inf")):
            continue
        if node == count - 1:
            break

        for neighbor, weight in adjacency.get(node, []):
            next_cost = current_cost + weight
            if next_cost < distances.get(neighbor, float("inf")):
                distances[neighbor] = next_cost
                previous[neighbor] = node
                heappush(queue, (next_cost, neighbor))

    path_indexes = [count - 1]
    while path_indexes[-1] != 0:
        parent = previous.get(path_indexes[-1])
        if parent is None:
            break
        path_indexes.append(parent)
    path_indexes.reverse()

    route_steps: list[RouteStep] = []
    cumulative_km = 0.0
    previous_point: tuple[Hop, float, float] | None = None

    for order, point_index in enumerate(path_indexes, start=1):
        hop, lat, lon = points[point_index]
        segment_km = 0.0
        if previous_point is not None:
            segment_km = haversine_km(previous_point[1], previous_point[2], lat, lon)
            cumulative_km += segment_km
        route_steps.append(
            RouteStep(
                order=order,
                hop=hop,
                lat=lat,
                lon=lon,
                segment_km=segment_km,
                cumulative_km=cumulative_km,
            )
        )
        previous_point = (hop, lat, lon)

    return route_steps, cumulative_km


def build_route_panel(target_label: str, route_steps: list[RouteStep], total_km: float) -> Element:
    if not route_steps:
        return Element(
            f"""
            <div style="position: fixed; top: 12px; right: 12px; z-index: 9999; width: 320px; max-height: calc(100vh - 24px); overflow: auto; background: rgba(15,23,42,0.94); color: white; padding: 14px 16px; border-radius: 16px; box-shadow: 0 10px 36px rgba(0,0,0,0.28); font-family: Segoe UI, Arial, sans-serif;">
                <div style="font-size: 15px; font-weight: 700; margin-bottom: 6px;">Ruta Dijkstra</div>
                <div style="font-size: 12px; line-height: 1.45; opacity: 0.9;">No hubo suficientes coordenadas geolocalizadas para construir una ruta visual.</div>
                <div style="margin-top: 10px; font-size: 12px; color: #94a3b8;">Destino: {target_label}</div>
            </div>
            """
        )

    items_html = []
    for step in route_steps:
        geo = step.hop.geolocation or {}
        location_bits = [geo.get("city"), geo.get("regionName"), geo.get("country")]
        location = ", ".join(bit for bit in location_bits if bit) or "Ubicación no disponible"
        segment_label = "Inicio" if step.order == 1 else f"{step.segment_km:.1f} km"
        rtt_label = f"{step.hop.rtt_ms:.1f} ms" if step.hop.rtt_ms is not None else "sin RTT"

        items_html.append(
            f"""
            <li style="margin: 0 0 10px 0; padding: 10px 10px 10px 12px; border-left: 3px solid #22c55e; background: rgba(15,23,42,0.55); border-radius: 10px;">
                <div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">
                    <strong style="font-size: 13px;">Paso {step.order} · TTL {step.hop.ttl}</strong>
                    <span style="font-size: 12px; color: #cbd5e1;">{segment_label}</span>
                </div>
                <div style="font-size: 12px; margin-top: 4px; color: #e2e8f0;">{step.hop.ip or 'sin respuesta'}</div>
                <div style="font-size: 12px; margin-top: 3px; color: #94a3b8;">{location}</div>
                <div style="font-size: 12px; margin-top: 3px; color: #94a3b8;">RTT: {rtt_label} · Acumulado: {step.cumulative_km:.1f} km</div>
            </li>
            """
        )

    return Element(
        f"""
        <div style="position: fixed; top: 12px; right: 12px; z-index: 9999; width: 340px; max-height: calc(100vh - 24px); overflow: auto; background: rgba(15,23,42,0.94); color: white; padding: 14px 16px; border-radius: 16px; box-shadow: 0 10px 36px rgba(0,0,0,0.28); font-family: Segoe UI, Arial, sans-serif; backdrop-filter: blur(8px);">
            <div style="font-size: 15px; font-weight: 800; margin-bottom: 4px;">Ruta Dijkstra</div>
            <div style="font-size: 12px; line-height: 1.45; opacity: 0.9; margin-bottom: 10px;">El algoritmo toma los saltos geolocalizados como nodos y calcula el camino con menor costo acumulado entre el primer y el último salto visible.</div>
            <div style="display:flex; gap: 10px; margin-bottom: 12px;">
                <div style="flex:1; background: rgba(34,197,94,0.14); border: 1px solid rgba(34,197,94,0.35); border-radius: 12px; padding: 10px;">
                    <div style="font-size: 11px; color: #a7f3d0; text-transform: uppercase; letter-spacing: 0.04em;">Saltos</div>
                    <div style="font-size: 20px; font-weight: 800; margin-top: 2px;">{len(route_steps)}</div>
                </div>
                <div style="flex:1; background: rgba(14,165,233,0.12); border: 1px solid rgba(14,165,233,0.3); border-radius: 12px; padding: 10px;">
                    <div style="font-size: 11px; color: #bae6fd; text-transform: uppercase; letter-spacing: 0.04em;">Costo</div>
                    <div style="font-size: 20px; font-weight: 800; margin-top: 2px;">{total_km:.1f} km</div>
                </div>
            </div>
            <div style="font-size: 12px; color: #cbd5e1; margin-bottom: 8px;">Destino: {target_label}</div>
            <ol style="list-style:none; padding:0; margin:0;">{''.join(items_html)}</ol>
        </div>
        """
    )


def build_map(hops: list[Hop], output_path: str, target_label: str) -> None:
    points = valid_geo_points(hops)
    route_steps, total_km = build_dijkstra_route(hops)
    route_points = [(step.lat, step.lon) for step in route_steps]

    if points:
        start_lat = points[0][1]
        start_lon = points[0][2]
    else:
        start_lat = 0.0
        start_lon = 0.0

    fmap = folium.Map(location=[start_lat, start_lon], zoom_start=3, tiles="OpenStreetMap")

    if route_points:
        folium.PolyLine(route_points, color="#64748b", weight=7, opacity=0.35).add_to(fmap)
        AntPath(route_points, color="#14b8a6", pulse_color="#facc15", weight=5, opacity=0.9).add_to(fmap)

    step_lookup = {step.hop.ttl: step for step in route_steps}
    for hop, lat, lon in points:
        geo = hop.geolocation or {}
        label_parts = [
            f"TTL {hop.ttl}",
            hop.ip or "sin respuesta",
        ]
        if hop.rtt_ms is not None:
            label_parts.append(f"{hop.rtt_ms:.1f} ms")

        popup_lines = [
            f"<b>{' | '.join(label_parts)}</b>",
            geo.get("city") or "",
            geo.get("regionName") or "",
            geo.get("country") or "",
            geo.get("isp") or geo.get("org") or "",
        ]
        popup_html = "<br>".join(part for part in popup_lines if part)

        folium.CircleMarker(
            location=[lat, lon],
            radius=6,
            color="#111827",
            fill=True,
            fill_color="#f59e0b",
            fill_opacity=0.95,
            popup=folium.Popup(popup_html, max_width=320),
            tooltip=f"TTL {hop.ttl} - {hop.ip}",
        ).add_to(fmap)

        step = step_lookup.get(hop.ttl)
        if step is not None:
            folium.Marker(
                location=[lat, lon],
                icon=DivIcon(
                    icon_size=(28, 28),
                    icon_anchor=(14, 14),
                    html=f"""
                    <div style="width: 28px; height: 28px; border-radius: 999px; background: #0f172a; border: 2px solid #22c55e; color: white; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; box-shadow: 0 4px 12px rgba(0,0,0,0.28);">{step.order}</div>
                    """,
                ),
            ).add_to(fmap)

    if points:
        last_hop, lat, lon = points[-1]
        final_label = last_hop.ip or target_label
        folium.Marker(
            location=[lat, lon],
            icon=folium.Icon(color="green", icon="flag"),
            popup=folium.Popup(f"Destino aproximado: {final_label}", max_width=260),
        ).add_to(fmap)

    title = Element(
        f"""
        <div style="position: fixed; top: 12px; left: 12px; z-index: 9999; background: rgba(17,24,39,0.92); color: white; padding: 12px 14px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.25); font-family: Arial, sans-serif; max-width: 260px;">
            <div style="font-size: 14px; font-weight: 700; margin-bottom: 4px;">Traceroute visual</div>
            <div style="font-size: 12px; opacity: 0.9; margin-bottom: 6px;">{target_label}</div>
            <div style="font-size: 11px; opacity: 0.85; line-height: 1.4;">La línea verde animada muestra la ruta observada y el panel derecho resume el camino mínimo calculado con Dijkstra sobre los saltos geolocalizados.</div>
        </div>
        """
    )
    fmap.get_root().html.add_child(title)
    fmap.get_root().html.add_child(build_route_panel(target_label, route_steps, total_km))
    fmap.save(output_path)


def execute_workflow(
    target: str,
    output_path: str,
    max_hops: int,
    timeout: float,
    probes_per_hop: int,
    logger=print,
) -> str:
    destination = resolve_target(target)
    logger(f"Destino resuelto: {target} -> {destination}")
    logger("Ejecutando traceroute...")
    hops = run_traceroute(destination, max_hops=max_hops, timeout=timeout, probes_per_hop=probes_per_hop)

    logger("Consultando geolocalización IP...")
    geolocator = GeoLocator()
    hops = enrich_hops_with_geo(hops, geolocator)

    route_steps, total_km = build_dijkstra_route(hops)
    if route_steps:
        logger(f"Camino Dijkstra: {len(route_steps)} saltos, {total_km:.1f} km acumulados")
    else:
        logger("Camino Dijkstra: sin coordenadas suficientes para construir una ruta")

    build_map(hops, output_path, target)
    logger(f"Mapa generado: {output_path}")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Traceroute con Scapy, geolocalización IP y mapa HTML con Folium.")
    parser.add_argument("target", nargs="?", help="Dominio o IP de destino")
    parser.add_argument("--output", default="traceroute_map.html", help="Archivo HTML de salida")
    parser.add_argument("--max-hops", type=int, default=30, help="Máximo de saltos")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout por intento en segundos")
    parser.add_argument("--probes", type=int, default=1, help="Probes por salto")
    parser.add_argument("--gui", action="store_true", help="Abrir la interfaz gráfica")
    return parser.parse_args()


class TracerouteApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Traceroute + mapa HTML")
        self.root.geometry("760x560")
        self.root.minsize(680, 500)

        self.target_var = tk.StringVar()
        self.output_var = tk.StringVar(value="traceroute_map.html")
        self.max_hops_var = tk.IntVar(value=30)
        self.timeout_var = tk.DoubleVar(value=2.0)
        self.probes_var = tk.IntVar(value=1)
        self.status_var = tk.StringVar(value="Listo")
        self.last_output_path: str | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        container = ttk.Frame(self.root, padding=16)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container)
        header.pack(fill=tk.X)
        ttk.Label(header, text="Traceroute + mapa HTML", font=("Segoe UI", 18, "bold")).pack(anchor=tk.W)
        ttk.Label(
            header,
            text="Ejecuta el traceroute, geolocaliza los saltos y abre un HTML con la ruta.",
        ).pack(anchor=tk.W, pady=(4, 14))

        form = ttk.Frame(container)
        form.pack(fill=tk.X)

        self._add_field(form, 0, "Destino", self.target_var)
        self._add_field(form, 1, "Salida HTML", self.output_var, browse=True)
        self._add_numeric_field(form, 2, "Máx. saltos", self.max_hops_var)
        self._add_numeric_field(form, 3, "Timeout (s)", self.timeout_var)
        self._add_numeric_field(form, 4, "Probes por salto", self.probes_var)

        actions = ttk.Frame(container)
        actions.pack(fill=tk.X, pady=(10, 8))
        self.run_button = ttk.Button(actions, text="Generar mapa", command=self.start_run)
        self.run_button.pack(side=tk.LEFT)
        ttk.Button(actions, text="Abrir HTML", command=self.open_output).pack(side=tk.LEFT, padx=(8, 0))

        status_row = ttk.Frame(container)
        status_row.pack(fill=tk.X, pady=(4, 8))
        ttk.Label(status_row, textvariable=self.status_var).pack(anchor=tk.W)

        log_frame = ttk.LabelFrame(container, text="Registro")
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log = scrolledtext.ScrolledText(log_frame, height=18, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.log.configure(state=tk.DISABLED)

    def _add_field(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, browse: bool = False) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.W, padx=(0, 10), pady=6)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky=tk.EW, pady=6)
        if browse:
            ttk.Button(parent, text="Examinar", command=self.choose_output).grid(row=row, column=2, padx=(8, 0), pady=6)
        parent.columnconfigure(1, weight=1)

    def _add_numeric_field(self, parent: ttk.Frame, row: int, label: str, variable: tk.Variable) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.W, padx=(0, 10), pady=6)
        spinbox = ttk.Spinbox(parent, textvariable=variable)
        spinbox.grid(row=row, column=1, sticky=tk.W, pady=6)

    def choose_output(self) -> None:
        filename = filedialog.asksaveasfilename(
            title="Guardar HTML",
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), (
                "Todos los archivos", "*.*"
            )],
            initialfile=self.output_var.get() or "traceroute_map.html",
        )
        if filename:
            self.output_var.set(filename)

    def append_log(self, message: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def start_run(self) -> None:
        target = self.target_var.get().strip()
        output_path = self.output_var.get().strip()
        if not target:
            messagebox.showerror("Falta destino", "Escribe un dominio o IP de destino.")
            return
        if not output_path:
            messagebox.showerror("Falta salida", "Elige un archivo HTML de salida.")
            return

        self.run_button.configure(state=tk.DISABLED)
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)
        self.set_status("Ejecutando...")

        def worker() -> None:
            try:
                result = execute_workflow(
                    target=target,
                    output_path=output_path,
                    max_hops=int(self.max_hops_var.get()),
                    timeout=float(self.timeout_var.get()),
                    probes_per_hop=int(self.probes_var.get()),
                    logger=self._threadsafe_log,
                )
            except socket.gaierror as exc:
                self.root.after(0, lambda: self._finish_with_error(f"No se pudo resolver el destino: {exc}"))
                return
            except Exception as exc:  # pragma: no cover - GUI safety net
                self.root.after(0, lambda: self._finish_with_error(f"Error: {exc}"))
                return

            self.root.after(0, lambda: self._finish_success(result))

        threading.Thread(target=worker, daemon=True).start()

    def _threadsafe_log(self, message: str) -> None:
        self.root.after(0, lambda: self.append_log(message))

    def _finish_success(self, output_path: str) -> None:
        self.last_output_path = output_path
        self.set_status(f"Mapa generado: {output_path}")
        self.run_button.configure(state=tk.NORMAL)

    def _finish_with_error(self, message: str) -> None:
        self.set_status("Error")
        self.run_button.configure(state=tk.NORMAL)
        messagebox.showerror("Ejecución fallida", message)
        self.append_log(message)

    def open_output(self) -> None:
        path = self.last_output_path or self.output_var.get().strip()
        if not path:
            messagebox.showinfo("Sin archivo", "Primero genera un mapa o selecciona una salida HTML.")
            return
        webbrowser.open(Path(path).resolve().as_uri())


def run_gui() -> None:
    root = tk.Tk()
    TracerouteApp(root)
    root.mainloop()


def main() -> int:
    args = parse_args()

    if args.gui or not args.target:
        run_gui()
        return 0

    try:
        execute_workflow(
            target=args.target,
            output_path=args.output,
            max_hops=args.max_hops,
            timeout=args.timeout,
            probes_per_hop=args.probes,
            logger=print,
        )
    except socket.gaierror as exc:
        print(f"No se pudo resolver el destino: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
