
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import (
    sniff,
    conf,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    Raw
)
import threading
import csv
from datetime import datetime


class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("NETWORK SNIFFER")
        self.root.geometry("1250x760")
        self.root.minsize(1050, 650)

        self.root.configure(bg="#10141a")

        self.running = False
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.other_count = 0

        self.packet_data = []
        self.current_packets = []

        # Your confirmed working Wi-Fi interface
        self.interface_index = 18

        self.setup_style()
        self.build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

    # ---------------------------------------------------------
    # STYLE
    # ---------------------------------------------------------

    def setup_style(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except:
            pass

        style.configure(
            "Treeview",
            background="#171c24",
            foreground="#e6edf3",
            fieldbackground="#171c24",
            rowheight=30,
            font=("Segoe UI", 10),
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            background="#202733",
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=8
        )

        style.map(
            "Treeview",
            background=[("selected", "#245a88")],
            foreground=[("selected", "#ffffff")]
        )

        style.configure(
            "TCombobox",
            fieldbackground="#171c24",
            background="#202733",
            foreground="#ffffff",
            arrowcolor="#ffffff"
        )

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------

    def build_ui(self):

        # ================= HEADER =================

        header = tk.Frame(
            self.root,
            bg="#10141a",
            height=80
        )
        header.pack(fill="x", padx=25, pady=(20, 5))
        header.pack_propagate(False)

        title_frame = tk.Frame(header, bg="#10141a")
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="NETWORK SNIFFER",
            font=("Segoe UI", 24, "bold"),
            fg="#ffffff",
            bg="#10141a"
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Real-time packet monitoring & analysis",
            font=("Segoe UI", 10),
            fg="#8f9baa",
            bg="#10141a"
        ).pack(anchor="w", pady=(2, 0))

        # Status

        status_frame = tk.Frame(
            header,
            bg="#10141a"
        )
        status_frame.pack(side="right", pady=15)

        self.status_dot = tk.Label(
            status_frame,
            text="●",
            font=("Segoe UI", 15),
            fg="#58d68d",
            bg="#10141a"
        )
        self.status_dot.pack(side="left", padx=(0, 7))

        self.status_label = tk.Label(
            status_frame,
            text="READY",
            font=("Segoe UI Semibold", 10),
            fg="#58d68d",
            bg="#10141a"
        )
        self.status_label.pack(side="left")

        # ================= CONTROL BAR =================

        control = tk.Frame(
            self.root,
            bg="#171c24",
            height=65
        )
        control.pack(fill="x", padx=25, pady=10)
        control.pack_propagate(False)

        # Interface

        tk.Label(
            control,
            text="INTERFACE",
            font=("Segoe UI Semibold", 9),
            fg="#8f9baa",
            bg="#171c24"
        ).pack(side="left", padx=(18, 8))

        self.interface_var = tk.StringVar(
            value="Intel(R) Wi-Fi 6 AX201 160MHz"
        )

        self.interface_combo = ttk.Combobox(
            control,
            textvariable=self.interface_var,
            state="readonly",
            width=35
        )

        self.interface_combo.pack(
            side="left",
            padx=(0, 15)
        )

        self.interface_combo["values"] = [
            "Intel(R) Wi-Fi 6 AX201 160MHz"
        ]

        # Start button

        self.start_button = tk.Button(
            control,
            text="▶  START CAPTURE",
            command=self.start_capture,
            font=("Segoe UI Semibold", 10),
            fg="#ffffff",
            bg="#2374b8",
            activebackground="#2d8bd4",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=16,
            pady=9,
            cursor="hand2"
        )
        self.start_button.pack(side="left", padx=4)

        # Stop button

        self.stop_button = tk.Button(
            control,
            text="■  STOP",
            command=self.stop_capture,
            font=("Segoe UI Semibold", 10),
            fg="#ffffff",
            bg="#a23b45",
            activebackground="#c44a55",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=16,
            pady=9,
            cursor="hand2",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=4)

        # Clear button

        self.clear_button = tk.Button(
            control,
            text="CLEAR",
            command=self.clear_packets,
            font=("Segoe UI Semibold", 10),
            fg="#ffffff",
            bg="#303944",
            activebackground="#414d5a",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=16,
            pady=9,
            cursor="hand2"
        )
        self.clear_button.pack(side="left", padx=4)

        # Export

        self.export_button = tk.Button(
            control,
            text="EXPORT CSV",
            command=self.export_csv,
            font=("Segoe UI Semibold", 10),
            fg="#ffffff",
            bg="#303944",
            activebackground="#414d5a",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=16,
            pady=9,
            cursor="hand2"
        )
        self.export_button.pack(side="right", padx=15)

        # ================= STAT CARDS =================

        stats = tk.Frame(
            self.root,
            bg="#10141a"
        )
        stats.pack(fill="x", padx=25, pady=(5, 12))

        self.total_value = self.create_stat_card(
            stats,
            "TOTAL PACKETS"
        )

        self.tcp_value = self.create_stat_card(
            stats,
            "TCP"
        )

        self.udp_value = self.create_stat_card(
            stats,
            "UDP"
        )

        self.other_value = self.create_stat_card(
            stats,
            "OTHER"
        )

        # ================= MAIN AREA =================

        main = tk.Frame(
            self.root,
            bg="#10141a"
        )
        main.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 20)
        )

        # Left side

        left = tk.Frame(
            main,
            bg="#171c24"
        )
        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        # Filter bar

        filter_frame = tk.Frame(
            left,
            bg="#171c24",
            height=48
        )
        filter_frame.pack(
            fill="x",
            padx=15,
            pady=(12, 5)
        )

        tk.Label(
            filter_frame,
            text="FILTER",
            font=("Segoe UI Semibold", 9),
            fg="#8f9baa",
            bg="#171c24"
        ).pack(side="left", padx=(0, 10))

        self.filter_var = tk.StringVar()

        self.filter_entry = tk.Entry(
            filter_frame,
            textvariable=self.filter_var,
            font=("Segoe UI", 10),
            bg="#202733",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat"
        )

        self.filter_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=8
        )

        self.filter_entry.insert(
            0,
            ""
        )

        self.filter_var.trace_add(
            "write",
            lambda *args: self.apply_filter()
        )

        # Packet table

        table_frame = tk.Frame(
            left,
            bg="#171c24"
        )
        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(5, 15)
        )

        columns = (
            "no",
            "time",
            "source",
            "destination",
            "protocol",
            "length",
            "info"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "no": "No.",
            "time": "Time",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "length": "Length",
            "info": "Info"
        }

        widths = {
            "no": 50,
            "time": 85,
            "source": 130,
            "destination": 130,
            "protocol": 80,
            "length": 70,
            "info": 230
        }

        for column in columns:
            self.tree.heading(
                column,
                text=headings[column]
            )

            self.tree.column(
                column,
                width=widths[column],
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_packet_details
        )

        # ================= RIGHT DETAILS =================

        right = tk.Frame(
            main,
            bg="#171c24",
            width=350
        )

        right.pack(
            side="right",
            fill="y"
        )

        right.pack_propagate(False)

        tk.Label(
            right,
            text="PACKET DETAILS",
            font=("Segoe UI Semibold", 12),
            fg="#ffffff",
            bg="#171c24"
        ).pack(
            anchor="w",
            padx=18,
            pady=(18, 3)
        )

        tk.Label(
            right,
            text="Select a packet to inspect its structure",
            font=("Segoe UI", 9),
            fg="#7f8b99",
            bg="#171c24"
        ).pack(
            anchor="w",
            padx=18,
            pady=(0, 12)
        )

        details_frame = tk.Frame(
            right,
            bg="#202733"
        )
        details_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0, 15)
        )

        self.details_text = tk.Text(
            details_frame,
            bg="#202733",
            fg="#dce3eb",
            font=("Consolas", 9),
            relief="flat",
            wrap="word",
            padx=12,
            pady=12,
            insertbackground="#ffffff"
        )

        self.details_text.pack(
            fill="both",
            expand=True
        )

        self.details_text.insert(
            "1.0",
            "No packet selected.\n\n"
            "Start a capture and select a packet\n"
            "from the table to inspect its details."
        )

        self.details_text.configure(
            state="disabled"
        )

    # ---------------------------------------------------------
    # STAT CARD
    # ---------------------------------------------------------

    def create_stat_card(self, parent, title):

        card = tk.Frame(
            parent,
            bg="#171c24",
            height=78
        )

        card.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )

        card.pack_propagate(False)

        tk.Label(
            card,
            text=title,
            font=("Segoe UI Semibold", 9),
            fg="#7f8b99",
            bg="#171c24"
        ).pack(
            anchor="w",
            padx=15,
            pady=(12, 0)
        )

        value = tk.Label(
            card,
            text="0",
            font=("Segoe UI", 22, "bold"),
            fg="#ffffff",
            bg="#171c24"
        )

        value.pack(
            anchor="w",
            padx=15,
            pady=(0, 8)
        )

        return value

    # ---------------------------------------------------------
    # START CAPTURE
    # ---------------------------------------------------------

    def start_capture(self):

        if self.running:
            return

        self.running = True

        self.status_label.config(
            text="CAPTURING"
        )

        self.status_dot.config(
            fg="#58d68d"
        )

        self.start_button.config(
            state="disabled"
        )

        self.stop_button.config(
            state="normal"
        )

        # Use the exact interface that was proven
        # to capture packets successfully.
        try:
            iface = conf.ifaces.dev_from_index(
                self.interface_index
            )

        except Exception as e:

            self.running = False

            self.status_label.config(
                text="ERROR"
            )

            self.status_dot.config(
                fg="#e74c3c"
            )

            messagebox.showerror(
                "Interface Error",
                "Could not access the Wi-Fi interface.\n\n"
                + str(e)
            )

            return

        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(iface,),
            daemon=True
        )

        self.capture_thread.start()

    # ---------------------------------------------------------
    # CAPTURE PACKETS
    # ---------------------------------------------------------

    def capture_packets(self, iface):

        try:

            sniff(
                iface=iface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda packet: not self.running
            )

        except Exception as e:

            self.root.after(
                0,
                lambda: self.capture_error(str(e))
            )

    # ---------------------------------------------------------
    # CAPTURE ERROR
    # ---------------------------------------------------------

    def capture_error(self, error):

        self.running = False

        self.status_label.config(
            text="ERROR"
        )

        self.status_dot.config(
            fg="#e74c3c"
        )

        self.start_button.config(
            state="normal"
        )

        self.stop_button.config(
            state="disabled"
        )

        messagebox.showerror(
            "Capture Error",
            "Packet capture stopped.\n\n"
            + error
        )

    # ---------------------------------------------------------
    # PACKET CALLBACK
    # ---------------------------------------------------------

    def packet_callback(self, packet):

        if not self.running:
            return

        try:

            timestamp = datetime.now().strftime(
                "%H:%M:%S.%f"
            )[:-3]

            source = "Unknown"
            destination = "Unknown"

            protocol = "OTHER"
            info = ""

            # ---------------- IP ----------------

            if IP in packet:

                source = packet[IP].src
                destination = packet[IP].dst

                if TCP in packet:

                    protocol = "TCP"

                    info = (
                        f"{packet[TCP].sport} → "
                        f"{packet[TCP].dport}"
                    )

                    if packet[TCP].flags:
                        info += (
                            f" | Flags: "
                            f"{packet[TCP].flags}"
                        )

                elif UDP in packet:

                    protocol = "UDP"

                    info = (
                        f"{packet[UDP].sport} → "
                        f"{packet[UDP].dport}"
                    )

                elif ICMP in packet:

                    protocol = "ICMP"

                    info = "ICMP packet"

                else:

                    protocol = "IP"

                    info = "IP packet"

            # ---------------- IPv6 ----------------

            elif IPv6 in packet:

                source = packet[IPv6].src
                destination = packet[IPv6].dst

                protocol = "IPv6"

                info = "IPv6 packet"

            # ---------------- ARP ----------------

            elif ARP in packet:

                source = packet[ARP].psrc
                destination = packet[ARP].pdst

                protocol = "ARP"

                if packet[ARP].op == 1:

                    info = (
                        f"Who has {packet[ARP].pdst}?"
                    )

                elif packet[ARP].op == 2:

                    info = (
                        f"{packet[ARP].psrc} is at "
                        f"{packet[ARP].hwsrc}"
                    )

                else:

                    info = "ARP packet"

            else:

                protocol = "OTHER"

                info = packet.summary()

            length = len(packet)

            packet_number = self.packet_count + 1

            record = {
                "no": packet_number,
                "time": timestamp,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "length": length,
                "info": info,
                "packet": packet
            }

            self.packet_data.append(record)

            self.packet_count += 1

            if protocol == "TCP":
                self.tcp_count += 1

            elif protocol == "UDP":
                self.udp_count += 1

            else:
                self.other_count += 1

            self.root.after(
                0,
                self.update_gui
            )

        except Exception:
            pass

    # ---------------------------------------------------------
    # UPDATE GUI
    # ---------------------------------------------------------

    def update_gui(self):

        if not self.running:
            return

        self.total_value.config(
            text=str(self.packet_count)
        )

        self.tcp_value.config(
            text=str(self.tcp_count)
        )

        self.udp_value.config(
            text=str(self.udp_count)
        )

        self.other_value.config(
            text=str(self.other_count)
        )

        # Only insert the latest packet.
        # This prevents unnecessary rebuilding
        # of the entire table.

        if not self.packet_data:
            return

        record = self.packet_data[-1]

        filter_text = (
            self.filter_var.get()
            .strip()
            .lower()
        )

        searchable = (
            f"{record['source']} "
            f"{record['destination']} "
            f"{record['protocol']} "
            f"{record['info']}"
        ).lower()

        if filter_text and filter_text not in searchable:
            return

        self.tree.insert(
            "",
            "end",
            values=(
                record["no"],
                record["time"],
                record["source"],
                record["destination"],
                record["protocol"],
                record["length"],
                record["info"]
            )
        )

        # Keep table scrolled to newest packet

        children = self.tree.get_children()

        if children:
            self.tree.see(children[-1])

    # ---------------------------------------------------------
    # FILTER
    # ---------------------------------------------------------

    def apply_filter(self):

        filter_text = (
            self.filter_var.get()
            .strip()
            .lower()
        )

        # Rebuild visible table

        for item in self.tree.get_children():
            self.tree.delete(item)

        for record in self.packet_data:

            searchable = (
                f"{record['source']} "
                f"{record['destination']} "
                f"{record['protocol']} "
                f"{record['info']}"
            ).lower()

            if (
                not filter_text
                or filter_text in searchable
            ):

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        record["no"],
                        record["time"],
                        record["source"],
                        record["destination"],
                        record["protocol"],
                        record["length"],
                        record["info"]
                    )
                )

    # ---------------------------------------------------------
    # PACKET DETAILS
    # ---------------------------------------------------------

    def show_packet_details(self, event=None):

        selected = self.tree.selection()

        if not selected:
            return

        item = selected[0]

        values = self.tree.item(
            item,
            "values"
        )

        if not values:
            return

        packet_number = int(values[0])

        record = None

        for p in self.packet_data:

            if p["no"] == packet_number:

                record = p
                break

        if record is None:
            return

        packet = record["packet"]

        details = []

        details.append(
            "PACKET INFORMATION"
        )

        details.append(
            "────────────────────────────"
        )

        details.append(
            f"Packet No.   : {record['no']}"
        )

        details.append(
            f"Time         : {record['time']}"
        )

        details.append(
            f"Protocol     : {record['protocol']}"
        )

        details.append(
            f"Length       : {record['length']} bytes"
        )

        details.append("")

        details.append(
            "NETWORK"
        )

        details.append(
            "────────────────────────────"
        )

        details.append(
            f"Source       : {record['source']}"
        )

        details.append(
            f"Destination  : {record['destination']}"
        )

        details.append("")

        details.append(
            "PACKET STRUCTURE"
        )

        details.append(
            "────────────────────────────"
        )

        details.append(
            packet.show(
                dump=True
            )
        )

        details.append("")

        details.append(
            "SUMMARY"
        )

        details.append(
            "────────────────────────────"
        )

        details.append(
            packet.summary()
        )

        self.details_text.configure(
            state="normal"
        )

        self.details_text.delete(
            "1.0",
            "end"
        )

        self.details_text.insert(
            "1.0",
            "\n".join(details)
        )

        self.details_text.configure(
            state="disabled"
        )

    # ---------------------------------------------------------
    # STOP
    # ---------------------------------------------------------

    def stop_capture(self):

        if not self.running:
            return

        self.running = False

        self.status_label.config(
            text="STOPPED"
        )

        self.status_dot.config(
            fg="#f4c542"
        )

        self.start_button.config(
            state="normal"
        )

        self.stop_button.config(
            state="disabled"
        )

    # ---------------------------------------------------------
    # CLEAR
    # ---------------------------------------------------------

    def clear_packets(self):

        if self.running:
            messagebox.showinfo(
                "Capture Running",
                "Stop the capture before clearing packets."
            )
            return

        self.packet_data.clear()

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.other_count = 0

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.total_value.config(text="0")
        self.tcp_value.config(text="0")
        self.udp_value.config(text="0")
        self.other_value.config(text="0")

        self.details_text.configure(
            state="normal"
        )

        self.details_text.delete(
            "1.0",
            "end"
        )

        self.details_text.insert(
            "1.0",
            "No packet selected.\n\n"
            "Start a capture and select a packet\n"
            "from the table to inspect its details."
        )

        self.details_text.configure(
            state="disabled"
        )

    # ---------------------------------------------------------
    # EXPORT CSV
    # ---------------------------------------------------------

    def export_csv(self):

        if not self.packet_data:

            messagebox.showinfo(
                "No Data",
                "There are no captured packets to export."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Export Packet Capture",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            initialfile="network_capture.csv"
        )

        if not filename:
            return

        try:

            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow(
                    [
                        "No.",
                        "Time",
                        "Source",
                        "Destination",
                        "Protocol",
                        "Length",
                        "Info"
                    ]
                )

                for record in self.packet_data:

                    writer.writerow(
                        [
                            record["no"],
                            record["time"],
                            record["source"],
                            record["destination"],
                            record["protocol"],
                            record["length"],
                            record["info"]
                        ]
                    )

            messagebox.showinfo(
                "Export Complete",
                f"Capture exported successfully.\n\n"
                f"File:\n{filename}"
            )

        except Exception as e:

            messagebox.showerror(
                "Export Error",
                str(e)
            )

    # ---------------------------------------------------------
    # CLOSE
    # ---------------------------------------------------------

    def close_app(self):

        self.running = False

        self.root.destroy()


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = NetworkSniffer(root)

    root.mainloop()

