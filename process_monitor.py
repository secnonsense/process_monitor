import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
import csv
import threading
import time
import subprocess
import shlex
import re
import socket
import sys
import os

class ProcessMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Monitor")
        self.root.geometry("1100x700")

        self.monitored_pid = None
        self.monitoring_active = False
        self.connections_data = []

        self.all_processes = []
        self.last_connections_data = []
        self.polling_interval = 1 # seconds
        self.last_checked_connections = set()
        
        self.sort_direction = {}

        self.create_widgets()
        self.populate_process_list()

    def create_widgets(self):
        # Main frames
        self.top_frame = ttk.Frame(self.root, padding="10")
        self.top_frame.pack(side="top", fill="both", expand=True)

        self.bottom_frame = ttk.Frame(self.root, padding="10")
        self.bottom_frame.pack(side="bottom", fill="both", expand=True)

        # Main control frame for dynamic view switching
        self.main_view_frame = ttk.Frame(self.top_frame)
        self.main_view_frame.pack(fill="both", expand=True)
        
        # Connections list (for single process monitoring)
        self.connections_label = ttk.Label(self.bottom_frame, text="Network Connections for Monitored Process", font=("Arial", 12, "bold"))
        self.connections_label.pack(pady=5)
        
        connections_columns = ("Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status")
        self.connections_tree = ttk.Treeview(self.bottom_frame, columns=connections_columns, show="headings")
        self.connections_tree.pack(pady=5, padx=5, fill="both", expand=True)
        for col in connections_columns:
            self.connections_tree.heading(col, text=col, command=lambda _col=col: self.sort_column(self.connections_tree, _col))
            self.connections_tree.column(col, width=150, anchor="center")
            
        # Export button
        export_button_frame = ttk.Frame(self.bottom_frame)
        export_button_frame.pack(pady=10)
        export_button = ttk.Button(export_button_frame, text="Export to CSV", command=self.export_to_csv)
        export_button.pack()
        
        # New: Create a separate, persistent filter box at the top
        self.net_filter_frame = ttk.Frame(self.top_frame)
        self.net_filter_frame.pack(pady=5)
        net_filter_label = ttk.Label(self.net_filter_frame, text="Filter Connections:", font=("Arial", 10))
        net_filter_label.pack(side="left", padx=5)
        self.net_filter_entry = ttk.Entry(self.net_filter_frame, width=50)
        self.net_filter_entry.pack(side="left", padx=5)
        self.net_filter_entry.bind("<KeyRelease>", self.apply_net_filter)

        # Process view frame (initially visible)
        self.process_view_frame = ttk.Frame(self.main_view_frame)
        self.process_view_frame.pack(fill="both", expand=True)
        
        # Search box for processes (remains in process view)
        search_frame = ttk.Frame(self.process_view_frame)
        search_frame.pack(pady=5)
        search_label = ttk.Label(search_frame, text="Search for Process:", font=("Arial", 10))
        search_label.pack(side="left", padx=5)
        self.search_box_entry = ttk.Entry(search_frame, width=50)
        self.search_box_entry.pack(side="left", padx=5)
        self.search_box_entry.bind("<KeyRelease>", self.filter_processes)

        # Process list
        process_label = ttk.Label(self.process_view_frame, text="Running Processes", font=("Arial", 12, "bold"))
        process_label.pack(pady=5)
        self.process_listbox = tk.Listbox(self.process_view_frame, width=100, height=20)
        self.process_listbox.pack(pady=5, padx=5, fill="both", expand=True)
        self.process_listbox_scrollbar = ttk.Scrollbar(self.process_listbox)
        self.process_listbox_scrollbar.pack(side="right", fill="y")
        self.process_listbox.config(yscrollcommand=self.process_listbox_scrollbar.set)
        self.process_listbox_scrollbar.config(command=self.process_listbox.yview)

        # Monitoring controls
        control_frame = ttk.Frame(self.process_view_frame)
        control_frame.pack(pady=10)
        self.monitor_button = ttk.Button(control_frame, text="Monitor Selected Process", command=self.start_monitoring)
        self.monitor_button.pack(side="left", padx=10)
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side="left", padx=10)
        
        # --- Show All Connections Button ---
        self.show_all_button = ttk.Button(control_frame, text="Show All Connections", command=self.show_all_connections)
        self.show_all_button.pack(side="left", padx=10)

        # --- Frame for all connections view ---
        self.all_connections_view_frame = ttk.Frame(self.main_view_frame)
        self.all_connections_view_frame.pack(fill="both", expand=True)

        # All Connections list
        all_connections_label = ttk.Label(self.all_connections_view_frame, text="All Network Connections", font=("Arial", 12, "bold"))
        all_connections_label.pack(pady=5)
        
        all_columns = ("Process", "PID", "Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status")
        self.all_connections_tree = ttk.Treeview(self.all_connections_view_frame, columns=all_columns, show="headings")
        self.all_connections_tree.pack(pady=5, padx=5, fill="both", expand=True)
        for col in all_columns:
            self.all_connections_tree.heading(col, text=col, command=lambda _col=col: self.sort_column(self.all_connections_tree, _col))
            self.all_connections_tree.column(col, width=150, anchor="center")

        # --- Return button for All Connections view ---
        return_frame = ttk.Frame(self.all_connections_view_frame)
        return_frame.pack(pady=10)
        self.return_button = ttk.Button(return_frame, text="Return to Process List", command=self.show_process_list)
        self.return_button.pack()
        
        self.all_connections_view_frame.pack_forget()

    def sort_column(self, tree, col):
        # Get the index of the column
        try:
            col_index = tree['columns'].index(col)
        except ValueError:
            return

        # Get all items in the treeview
        data = [(tree.set(child, col), child) for child in tree.get_children('')]

        # Get the current sort direction, default to ascending
        current_direction = self.sort_direction.get(col, False) # False for ascending
        
        # Determine the new sort direction
        new_direction = not current_direction
        self.sort_direction[col] = new_direction

        # Sort the data using a more robust key function
        # This key function handles both numerical and string values.
        # It creates a tuple: (True/False for numerical, actual value).
        def sort_key(item):
            value = item[0]
            try:
                # Attempt to convert to float. This works for numbers, including those in string format.
                return (True, float(value))
            except (ValueError, TypeError):
                # If conversion fails, it's a string, so we return a tuple with False.
                return (False, value.lower()) if isinstance(value, str) else (False, value)

        data.sort(key=sort_key, reverse=new_direction)
        
        # Rearrange the treeview items
        for index, (val, child) in enumerate(data):
            tree.move(child, '', index)

    def populate_process_list(self):
        self.all_processes.clear()
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pinfo = proc.info
                self.all_processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        self.filter_processes()

    def filter_processes(self, event=None):
        search_term = self.search_box_entry.get().lower()
        self.process_listbox.delete(0, tk.END)
        for pinfo in self.all_processes:
            try:
                if search_term in pinfo['name'].lower() or (pinfo['username'] and search_term in pinfo['username'].lower()):
                    self.process_listbox.insert(tk.END, f"PID: {pinfo['pid']} | Name: {pinfo['name']} | User: {pinfo['username']}")
            except TypeError:
                continue

    def apply_net_filter(self, event=None):
        filter_term = self.net_filter_entry.get().lower()
            
        if self.monitored_pid: # Filtering for a single process
            self.connections_tree.delete(*self.connections_tree.get_children())
            for row_data in self.last_connections_data:
                local_ip, local_port, resolved_host, remote_ip, remote_port, status = row_data
                if not filter_term or filter_term in str(resolved_host).lower() or filter_term in str(remote_ip).lower() or filter_term in str(remote_port):
                    self.connections_tree.insert("", "end", values=row_data)
        else: # Filtering for all connections
            self.all_connections_tree.delete(*self.all_connections_tree.get_children())
            for row_data in self.last_connections_data:
                process_name, pid, local_ip, local_port, resolved_host, remote_ip, remote_port, status = row_data
                if not filter_term or filter_term in str(resolved_host).lower() or filter_term in str(remote_ip).lower() or filter_term in str(remote_port) or filter_term in str(pid):
                    self.all_connections_tree.insert("", "end", values=row_data)

    def get_selected_pid(self):
        try:
            selection = self.process_listbox.curselection()
            if not selection:
                return None
            selected_text = self.process_listbox.get(selection[0])
            pid_str = selected_text.split(" ")[1]
            return int(pid_str)
        except IndexError:
            return None

    def start_monitoring(self):
        self.monitored_pid = self.get_selected_pid()
        if self.monitored_pid is None:
            messagebox.showwarning("No Selection", "Please select a process to monitor.")
            return

        self.monitoring_active = True
        self.last_connections_data = [] # Clear old data for new monitoring session
        self.last_checked_connections = set()
        self.connections_tree.delete(*self.connections_tree.get_children()) # Clear the GUI table
        
        self.monitor_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        messagebox.showinfo("Monitoring", f"Started monitoring process with PID: {self.monitored_pid}")
        
        self.monitor_thread = threading.Thread(target=self.monitor_connections_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring_active = False
        self.monitored_pid = None
        self.monitor_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        messagebox.showinfo("Monitoring Stopped", "Monitoring has been stopped. The last known connections are displayed.")
    
    def show_all_connections(self):
        self.stop_monitoring()
        self.process_view_frame.pack_forget()
        self.bottom_frame.pack_forget()
        self.all_connections_view_frame.pack(fill="both", expand=True)
        self.get_all_connections()
        
    def show_process_list(self):
        self.all_connections_view_frame.pack_forget()
        self.process_view_frame.pack(fill="both", expand=True)
        self.bottom_frame.pack(side="bottom", fill="both", expand=True)
        self.last_connections_data = []
        self.apply_net_filter()

    def get_all_connections(self):
        self.last_connections_data = []
        try:
            lsof_command = "lsof -i -a"
            output = subprocess.check_output(shlex.split(lsof_command), stderr=subprocess.DEVNULL).decode('utf-8')

            for line in output.splitlines():
                if line.startswith("COMMAND"):
                    continue

                parts = line.split()
                if not parts:
                    continue

                process_name = parts[0]
                pid = parts[1]

                local_ip, local_port, resolved_host, remote_ip, remote_port, status = "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"

                address_data = None
                for part in parts:
                    if '->' in part:
                        address_data = part
                        break

                if not address_data:
                    try:
                        address_data = [p for p in parts if ':' in p][0]
                        local_ip, local_port = self.parse_address(address_data)
                        status = parts[-1] if 'ESTABLISHED' in line or 'LISTEN' in line else "N/A"
                    except IndexError:
                        continue 
                else:
                    local_addr_str, remote_addr_str = address_data.split('->')
                    local_ip, local_port = self.parse_address(local_addr_str)
                    remote_host_or_ip, remote_port = self.parse_address(remote_addr_str)
                    
                    if 'LISTEN' in line:
                         status = 'LISTEN'
                    elif '(ESTABLISHED)' in line:
                         status = 'ESTABLISHED'
                    elif '(SYN_SENT)' in line:
                        status = 'SYN_SENT'
                    else:
                        status = "N/A"

                    if remote_host_or_ip:
                        if self.is_valid_ip(remote_host_or_ip):
                            remote_ip = remote_host_or_ip
                            if remote_ip != "*":
                                resolved_host = self.get_resolved_host(remote_ip)
                        else:
                            resolved_host = remote_host_or_ip
                            if resolved_host != "*":
                                remote_ip = self.get_resolved_ip(resolved_host)
                
                row_data = (process_name, pid, local_ip, local_port, resolved_host, remote_ip, remote_port, status)
                self.last_connections_data.append(row_data)
        
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Command failed with error: {e.output.decode('utf-8')}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

        self.apply_net_filter()

    def monitor_connections_loop(self):
        while self.monitoring_active:
            self.update_connections()
            time.sleep(self.polling_interval)

    def get_numerical_port(self, port_string):
        try:
            return int(port_string)
        except ValueError:
            try:
                return socket.getservbyname(port_string)
            except socket.error:
                return "N/A"

    def is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def get_resolved_host(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, IndexError):
            return "N/A"
        except Exception:
            return "Error"

    def get_resolved_ip(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except (socket.herror, socket.gaierror):
            return "N/A"
        except Exception:
            return "Error"

    def parse_address(self, address_str):
        if ':' in address_str:
            parts = address_str.rsplit(':', 1)
            host = parts[0]
            port = self.get_numerical_port(parts[1])
            return host, port
        return address_str, "N/A"

    def update_connections(self):
        if not self.monitoring_active:
            return

        try:
            process_name = psutil.Process(self.monitored_pid).name()
            pgrep_command = f"pgrep {shlex.quote(process_name)}"
            pids = subprocess.check_output(shlex.split(pgrep_command)).decode().strip().split('\n')
            pids_string = ",".join(pids)

            if not pids_string:
                return

            lsof_command = f"lsof -i -a -p {pids_string}"
            output = subprocess.check_output(shlex.split(lsof_command), stderr=subprocess.DEVNULL).decode('utf-8')
            
            current_connections_set = set()
            filter_term = self.net_filter_entry.get().lower()

            for line in output.splitlines():
                if line.startswith("COMMAND"):
                    continue

                local_ip, local_port, resolved_host, remote_ip, remote_port, status = "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"

                parts = line.split()

                address_data = None
                for part in parts:
                    if '->' in part:
                        address_data = part
                        break

                if not address_data:
                    try:
                        address_data = [p for p in parts if ':' in p][0]
                        local_ip, local_port = self.parse_address(address_data)
                        status = parts[-1] if 'ESTABLISHED' in line or 'LISTEN' in line else "N/A"
                    except IndexError:
                        continue 
                else:
                    local_addr_str, remote_addr_str = address_data.split('->')
                    local_ip, local_port = self.parse_address(local_addr_str)
                    remote_host_or_ip, remote_port = self.parse_address(remote_addr_str)
                    
                    if 'LISTEN' in line:
                         status = 'LISTEN'
                    elif '(ESTABLISHED)' in line:
                         status = 'ESTABLISHED'
                    elif '(SYN_SENT)' in line:
                        status = 'SYN_SENT'
                    else:
                        status = "N/A"

                    if remote_host_or_ip:
                        if self.is_valid_ip(remote_host_or_ip):
                            remote_ip = remote_host_or_ip
                            if remote_ip != "*":
                                resolved_host = self.get_resolved_host(remote_ip)
                        else:
                            resolved_host = remote_host_or_ip
                            if resolved_host != "*":
                                remote_ip = self.get_resolved_ip(resolved_host)
                
                row_data = (local_ip, local_port, resolved_host, remote_ip, remote_port, status)
                current_connections_set.add(row_data)
            
            # Check for new connections and add them, applying the filter
            new_connections = current_connections_set - self.last_checked_connections
            
            for conn in new_connections:
                # Apply filter to new connections before adding them to the treeview
                local_ip, local_port, resolved_host, remote_ip, remote_port, status = conn
                if not filter_term or filter_term in str(resolved_host).lower() or filter_term in str(remote_ip).lower() or filter_term in str(remote_port):
                    self.last_connections_data.append(conn)
                    self.connections_tree.insert("", "end", values=conn)
                else:
                    self.last_connections_data.append(conn)
            self.last_checked_connections = current_connections_set

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            if self.monitoring_active:
                messagebox.showerror("Error", f"Could not monitor process: {e}")
                self.stop_monitoring()
        except subprocess.CalledProcessError as e:
            if self.monitoring_active:
                messagebox.showerror("Error", f"Command failed with error: {e.output.decode('utf-8')}")
                self.stop_monitoring()
        except Exception as e:
            if self.monitoring_active:
                messagebox.showerror("Error", f"An unexpected error occurred: {e}")
                self.stop_monitoring()
            
    def export_to_csv(self):
        if not self.last_connections_data:
            messagebox.showwarning("No Data", "No network connections to export.")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                if self.monitored_pid:
                    writer.writerow(["Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status"])
                else:
                    writer.writerow(["Process", "PID", "Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status"])
                writer.writerows(self.last_connections_data)
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")

if __name__ == "__main__":
    if sys.platform != 'linux':
        pass
    root = tk.Tk()
    app = ProcessMonitorApp(root)
    root.mainloop()
