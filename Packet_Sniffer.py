import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import scapy.all as scapy
import threading
import queue
import binascii
import time
from datetime import datetime

PROTOCOL_DESCRIPTIONS = {
    "Ethernet": "The data link layer protocol for wired local area networks.",
    "IP": "The primary protocol for routing data packets across networks (IPv4).",
    "IPv6": "The newer version of the Internet Protocol.",
    "TCP": "A reliable, connection-oriented protocol used for applications like web browsing and email.",
    "UDP": "A simple, connectionless protocol often used for streaming and online gaming.",
    "ARP": "Used to map IP addresses to physical MAC addresses on a local network.",
    "ICMP": "Used for sending error messages and operational information about the network (IPv4).",
    "ICMPv6": "Used for sending error messages and operational information about the network (IPv6).",
    "DHCP": "Used to automatically assign IP addresses and other network configuration parameters.",
    "DHCP6": "DHCP for IPv6.",
    "DNS": "Used to translate domain names into IP addresses.",
    "HTTP": "The foundation of data communication for the World Wide Web.",
    "HTTPS": "Secure version of HTTP, encrypted using TLS/SSL.",
    "FTP": "Used for transferring files between a client and server.",
    "SMTP": "Used for sending email messages.",
    "POP3": "Used for receiving email messages.",
    "IMAP": "Used for accessing and managing email messages on a server.",
    "SNMP": "Used for managing and monitoring network devices.",
    "SSH": "A secure protocol used for remote command-line login and execution.",
    "TLS": "A cryptographic protocol providing end-to-end security for data transmitted over the Internet.",
    "SSL": "Older version of TLS.",
}

sniffing_thread = None
stop_sniffing_event = threading.Event()
packet_queue = queue.Queue()
packet_details = {}
packet_counter = 0

def get_protocol_layers(packet):
    layers = []
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        layers.append(layer.name)
        counter += 1
    return layers

def get_packet_summary(packet):
    src = "N/A"
    dst = "N/A"
    proto = "N/A"
    layers = get_protocol_layers(packet)
    proto = " / ".join(layers)

    if packet.haslayer(scapy.IP):
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst
    elif packet.haslayer(scapy.IPv6):
        src = packet[scapy.IPv6].src
        dst = packet[scapy.IPv6].dst
    elif packet.haslayer(scapy.ARP):
        src = packet[scapy.ARP].psrc
        dst = packet[scapy.ARP].pdst
        proto = "ARP"
    elif packet.haslayer(scapy.Ether):
        src = packet[scapy.Ether].src
        dst = packet[scapy.Ether].dst
        if not layers:
             proto = "Ethernet"

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    length = len(packet)

    return f"{timestamp} | Len: {length} | {src} -> {dst} | Proto: {proto}"

def packet_callback(packet):
    if stop_sniffing_event.is_set():
        return

    global packet_counter
    packet_counter += 1
    packet_id = f"pkt_{packet_counter}"

    summary = get_packet_summary(packet)
    raw_packet_data = bytes(packet)

    packet_details[packet_id] = (summary, raw_packet_data, packet)

    packet_queue.put((packet_id, summary))

def start_sniffing_thread():
    global sniffing_thread
    if sniffing_thread is not None and sniffing_thread.is_alive():
        messagebox.showwarning("Sniffer", "Sniffing is already running.")
        return

    stop_sniffing_event.clear()
    packet_queue.queue.clear()
    packet_details.clear()
    global packet_counter
    packet_counter = 0
    packet_list.delete(*packet_list.get_children())
    protocol_info_text.config(state=tk.NORMAL)
    protocol_info_text.delete('1.0', tk.END)
    protocol_info_text.config(state=tk.DISABLED)
    packet_data_text.config(state=tk.NORMAL)
    packet_data_text.delete('1.0', tk.END)
    packet_data_text.config(state=tk.DISABLED)
    status_label.config(text="Status: Starting...")
    download_button.config(state=tk.DISABLED)


    def run_sniffer():
        try:
            status_label.config(text="Status: Sniffing...")
            scapy.sniff(prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing_event.is_set())
            status_label.config(text="Status: Stopped")
        except PermissionError:
             messagebox.showerror("Permission Error", "Need root/administrator privileges to sniff packets.")
             status_label.config(text="Status: Error (Permissions)")
        except OSError as e:
             messagebox.showerror("Interface Error", f"Error starting sniffer: {e}\nCheck network interface permissions or availability.")
             status_label.config(text="Status: Error (Interface)")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            status_label.config(text=f"Status: Error ({type(e).__name__})")
        finally:
             start_button.config(state=tk.NORMAL)
             stop_button.config(state=tk.DISABLED)


    sniffing_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffing_thread.start()

    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)


def stop_sniffing():
    if sniffing_thread is None or not sniffing_thread.is_alive():
        messagebox.showinfo("Sniffer", "Sniffing is not currently running.")
        return

    stop_sniffing_event.set()
    status_label.config(text="Status: Stopping...")
    root.after(100, check_thread_stopped)

def check_thread_stopped():
     if sniffing_thread is None or not sniffing_thread.is_alive():
         status_label.config(text="Status: Stopped")
         start_button.config(state=tk.NORMAL)
         stop_button.config(state=tk.DISABLED)
     else:
         root.after(100, check_thread_stopped)


def update_packet_list():
    try:
        while not packet_queue.empty():
            packet_id, summary = packet_queue.get_nowait()
            packet_list.insert("", 0, iid=packet_id, values=(packet_id.split('_')[1], summary))
            if len(packet_list.get_children()) > 1000:
                 oldest_item = packet_list.get_children()[-1]
                 if oldest_item in packet_details:
                     del packet_details[oldest_item]
                 packet_list.delete(oldest_item)

    except queue.Empty:
        pass
    finally:
        root.after(100, update_packet_list)

def show_packet_details(event):
    selected_items = packet_list.selection()
    if not selected_items:
        return

    packet_id = selected_items[0]

    if packet_id in packet_details:
        summary, raw_data, packet_obj = packet_details[packet_id]

        protocol_info_text.config(state=tk.NORMAL)
        protocol_info_text.delete('1.0', tk.END)

        layers = get_protocol_layers(packet_obj)
        protocol_info_text.insert(tk.END, "Detected Protocols:\n", "bold")
        for layer_name in layers:
            description = PROTOCOL_DESCRIPTIONS.get(layer_name, "No description available.")
            protocol_info_text.insert(tk.END, f"- {layer_name}: {description}\n")

        protocol_info_text.insert(tk.END, "\n--- Scapy Summary ---\n", "bold")
        try:
            import io
            from contextlib import redirect_stdout
            f = io.StringIO()
            with redirect_stdout(f):
                packet_obj.show()
            scapy_summary = f.getvalue()
            protocol_info_text.insert(tk.END, scapy_summary)
        except Exception as e:
            protocol_info_text.insert(tk.END, f"Error generating Scapy summary: {e}")

        protocol_info_text.config(state=tk.DISABLED)

        packet_data_text.config(state=tk.NORMAL)
        packet_data_text.delete('1.0', tk.END)
        packet_data_text.insert(tk.END, "Raw Packet Data (Hexdump):\n", "bold")

        line_len = 16
        ascii_repr = ""
        for i in range(0, len(raw_data), line_len):
            chunk = raw_data[i:i+line_len]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)

            packet_data_text.insert(tk.END, f"{i:08x}  {hex_part:<{line_len*3}} |{ascii_part}|\n")

        packet_data_text.config(state=tk.DISABLED)

        download_button.config(state=tk.NORMAL)
    else:
        protocol_info_text.config(state=tk.NORMAL)
        protocol_info_text.delete('1.0', tk.END)
        protocol_info_text.config(state=tk.DISABLED)
        packet_data_text.config(state=tk.NORMAL)
        packet_data_text.delete('1.0', tk.END)
        packet_data_text.config(state=tk.DISABLED)
        download_button.config(state=tk.DISABLED)


def download_packet():
    selected_items = packet_list.selection()
    if not selected_items:
        messagebox.showwarning("Download", "Please select a packet from the list first.")
        return

    packet_id = selected_items[0]
    if packet_id in packet_details:
        summary, raw_data, packet_obj = packet_details[packet_id]

        suggested_filename = f"packet_{packet_id}.bin"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".bin",
            initialfile=suggested_filename,
            filetypes=[("Binary files", "*.bin"), ("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if not filepath:
            return

        try:
            if filepath.lower().endswith(".pcap"):
                 scapy.wrpcap(filepath, [packet_obj])
                 messagebox.showinfo("Download Complete", f"Packet saved as PCAP:\n{filepath}")
            else:
                 with open(filepath, 'wb') as f:
                     f.write(raw_data)
                 messagebox.showinfo("Download Complete", f"Packet raw data saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Download Error", f"Failed to save packet: {e}")
    else:
        messagebox.showerror("Download Error", "Selected packet details not found.")


root = tk.Tk()
root.title("Python Packet Sniffer")
root.geometry("1000x700")

style = ttk.Style()
style.theme_use('clam')
style.configure("Treeview.Heading", font=('Calibri', 10,'bold'))
style.configure("Treeview", rowheight=25, font=('Calibri', 10))
style.configure("TButton", padding=6, relief="flat", font=('Calibri', 10))
style.configure("TLabel", padding=5, font=('Calibri', 10))

main_pane = ttk.PanedWindow(root, orient=tk.VERTICAL)
main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

top_pane = ttk.Frame(main_pane, padding="5")
main_pane.add(top_pane, weight=1)

bottom_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
main_pane.add(bottom_pane, weight=2)

control_frame = ttk.Frame(top_pane)
control_frame.pack(pady=5, fill=tk.X)

start_button = ttk.Button(control_frame, text="Start Sniffing", command=start_sniffing_thread)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=5)

status_label = ttk.Label(control_frame, text="Status: Idle")
status_label.pack(side=tk.LEFT, padx=10)

list_frame = ttk.Frame(top_pane)
list_frame.pack(fill=tk.BOTH, expand=True, pady=(5,0))

columns = ("id", "summary")
packet_list = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
packet_list.heading("id", text="ID")
packet_list.heading("summary", text="Packet Summary")
packet_list.column("id", width=50, anchor=tk.CENTER)
packet_list.column("summary", width=700)

scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=packet_list.yview)
packet_list.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

packet_list.bind("<<TreeviewSelect>>", show_packet_details)

proto_frame = ttk.Frame(bottom_pane, padding="5")
bottom_pane.add(proto_frame, weight=1)

proto_label = ttk.Label(proto_frame, text="Protocol Information & Description:")
proto_label.pack(anchor=tk.NW)

protocol_info_text = scrolledtext.ScrolledText(proto_frame, wrap=tk.WORD, height=15, font=("Consolas", 9), state=tk.DISABLED)
protocol_info_text.pack(fill=tk.BOTH, expand=True, pady=(0,5))
protocol_info_text.tag_config("bold", font=("Consolas", 9, "bold"))

data_frame = ttk.Frame(bottom_pane, padding="5")
bottom_pane.add(data_frame, weight=2)

data_label = ttk.Label(data_frame, text="Packet Data (Hexdump):")
data_label.pack(anchor=tk.NW)

packet_data_text = scrolledtext.ScrolledText(data_frame, wrap=tk.NONE, height=15, font=("Consolas", 9), state=tk.DISABLED)
packet_data_text.pack(fill=tk.BOTH, expand=True, pady=(0,5))
packet_data_text.tag_config("bold", font=("Consolas", 9, "bold"))

download_button = ttk.Button(data_frame, text="Download Selected Packet", command=download_packet, state=tk.DISABLED)
download_button.pack(pady=5)

root.after(100, update_packet_list)

def on_closing():
    if sniffing_thread and sniffing_thread.is_alive():
        if messagebox.askokcancel("Quit", "Sniffer is running. Stop sniffing and quit?"):
            stop_sniffing_event.set()
            root.after(200, root.destroy)
        else:
            return
    else:
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
