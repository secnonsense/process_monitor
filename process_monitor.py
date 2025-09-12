import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import shlex
import threading
import time
import socket
import sys
import psutil
import csv
import queue

class ProcessMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("All Network Connections (Historical View)")
        self.root.geometry("1100x700")

        self.all_connections_data = {}
        self.polling_interval = 1
        self.sort_direction = {}
        self.sort_column_name = None
        self.filter_vars = {}
        self.data_queue = queue.Queue()
        
        self.create_widgets()
        self.start_monitoring_all_connections()
        self.root.after(100, self.process_queue)

    def create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(side="top", fill="both", expand=True)

        title_label = ttk.Label(self.main_frame, text="All Network Connections", font=("Arial", 14, "bold"))
        title_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(self.main_frame, orient="horizontal", mode="indeterminate", length=200)
        self.progress_bar.pack(pady=5)
        self.progress_bar.start()

        all_columns = ("Process", "PID", "Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status")

        self.filter_frame = ttk.Frame(self.main_frame)
        self.filter_frame.pack(pady=5, fill="x")

        self.all_connections_tree = ttk.Treeview(self.main_frame, columns=all_columns, show="headings")
        self.all_connections_tree.pack(pady=5, padx=5, fill="both", expand=True)
        
        self.create_column_headers(all_columns)
        self.create_aligned_filters(all_columns)

        export_button = ttk.Button(self.main_frame, text="Export to CSV (Current View)", command=self.export_to_csv)
        export_button.pack(pady=10)
        
        self.stop_button = ttk.Button(self.main_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.NORMAL)
        self.stop_button.pack(pady=5)

    def create_column_headers(self, columns):
        self.all_connections_tree.column("#0", width=0, stretch=tk.NO)
        for col in columns:
            self.all_connections_tree.heading(col, text=col, command=lambda _col=col: self.sort_column_trigger(_col))
            self.all_connections_tree.column(col, width=120, anchor="center")

    def create_aligned_filters(self, columns):
        self.filter_widgets = {}
        self.filter_vars = {col: tk.StringVar() for col in columns}

        def _update_filter(event):
            self.apply_filters()

        for col_name in columns:
            filter_entry = ttk.Entry(self.filter_frame, textvariable=self.filter_vars[col_name], width=15)
            filter_entry.pack(side="left", fill="x", expand=True, padx=2)
            filter_entry.insert(0, f"Filter {col_name}")
            filter_entry.bind("<KeyRelease>", _update_filter)
            self.filter_widgets[col_name] = filter_entry
            
            def clear_placeholder_on_focus(event):
                if event.widget.get().startswith("Filter"):
                    event.widget.delete(0, tk.END)
                    event.widget.config(foreground='black')
            
            def add_placeholder_on_focusout(event):
                if not event.widget.get():
                    col_key = next((key for key, value in self.filter_widgets.items() if value == event.widget), None)
                    if col_key:
                        event.widget.insert(0, f"Filter {col_key}")
                        event.widget.config(foreground='gray')

            filter_entry.bind("<FocusIn>", clear_placeholder_on_focus)
            filter_entry.bind("<FocusOut>", add_placeholder_on_focusout)

    def apply_filters(self, event=None):
        self.update_display()
        
    def sort_column_trigger(self, col):
        # Trigger a sort and flip direction on user click
        if self.sort_column_name == col:
            self.sort_direction[col] = not self.sort_direction.get(col, True)
        else:
            self.sort_column_name = col
            self.sort_direction[col] = True # Default to ascending on new column
        self.update_display()

    def update_display(self):
        filters = {col: var.get().lower() for col, var in self.filter_vars.items() if var.get() and not var.get().startswith("Filter")}
        
        current_displayed_items = {self.all_connections_tree.item(item, 'values') for item in self.all_connections_tree.get_children('')}
        
        filtered_data = []
        for row_data_tuple in self.all_connections_data.keys():
            if all(self.is_match(row_data_tuple, filters, col) for col in filters):
                filtered_data.append(row_data_tuple)
        
        if self.sort_column_name:
            col_index = self.all_connections_tree["columns"].index(self.sort_column_name)
            reverse = not self.sort_direction.get(self.sort_column_name, True)
            
            def sort_key(item):
                value = item[col_index]
                try:
                    return (True, float(value))
                except (ValueError, TypeError):
                    return (False, str(value).lower())

            filtered_data.sort(key=sort_key, reverse=reverse)
        
        filtered_data_set = set(filtered_data)
        
        items_to_add = filtered_data_set - current_displayed_items
        items_to_remove = current_displayed_items - filtered_data_set
        
        for item_values in items_to_remove:
            for child in self.all_connections_tree.get_children():
                if self.all_connections_tree.item(child, 'values') == item_values:
                    self.all_connections_tree.delete(child)
                    break
        
        for item_values in items_to_add:
            self.all_connections_tree.insert("", "end", values=item_values)

        if self.sort_column_name:
            self.all_connections_tree.delete(*self.all_connections_tree.get_children())
            for item in filtered_data:
                self.all_connections_tree.insert("", "end", values=item)

    def is_match(self, row_data, filters, col):
        col_index = self.all_connections_tree["columns"].index(col)
        value = str(row_data[col_index]).lower()
        filter_text = filters.get(col, "")
        return filter_text in value

    def sort_column(self, tree, col):
        self.sort_column_name = col
        try:
            col_index = tree['columns'].index(col)
        except ValueError:
            return

        data = [(tree.set(child, col), child) for child in tree.get_children('')]
        
        current_direction = self.sort_direction.get(col, True) # True for ascending
        new_direction = not current_direction
        self.sort_direction[col] = new_direction
        
        def sort_key(item):
            value = item[0]
            try:
                return float(value)
            except (ValueError, TypeError):
                return value.lower() if isinstance(value, str) else value
        
        sorted_data = sorted(data, key=sort_key, reverse=new_direction)
        
        for index, (val, child) in enumerate(sorted_data):
            tree.move(child, '', index)

    def start_monitoring_all_connections(self):
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self.monitor_all_connections_loop, daemon=True)
        self.monitor_thread.start()

    def process_queue(self):
        try:
            while not self.data_queue.empty():
                new_connections = self.data_queue.get_nowait()
                for conn in new_connections:
                    self.all_connections_data[conn] = True
                self.update_display()
                self.progress_bar.stop()
                self.progress_bar.pack_forget()

        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def stop_monitoring(self):
        self.monitoring_active = False
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        messagebox.showinfo("Monitoring Stopped", "Monitoring has been stopped.")

    def monitor_all_connections_loop(self):
        while self.monitoring_active:
            self.get_all_connections()
            time.sleep(self.polling_interval)
    
    def get_all_connections(self):
        current_connections_set = set()
        pid_name_map = {}
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                pid_name_map[str(proc.info['pid'])] = proc.info['name']

            lsof_command = "lsof -i -a"
            output = subprocess.check_output(shlex.split(lsof_command), stderr=subprocess.DEVNULL).decode('utf-8')
            
            for line in output.splitlines():
                if line.startswith("COMMAND") or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                pid = parts[1]
                process_name = pid_name_map.get(pid, parts[0])
                
                local_ip, local_port, resolved_host, remote_ip, remote_port, status = "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
                
                address_data = None
                for part in parts:
                    if '->' in part or ':' in part:
                        address_data = part
                        break

                if address_data:
                    if '->' in address_data:
                        local_addr_str, remote_addr_str = address_data.split('->')
                        local_ip, local_port = self.parse_address(local_addr_str)
                        remote_host_or_ip, remote_port = self.parse_address(remote_addr_str)
                        
                        if remote_host_or_ip and self.is_valid_ip(remote_host_or_ip):
                            remote_ip = remote_host_or_ip
                            resolved_host = self.get_resolved_host(remote_ip)
                        else:
                            resolved_host = remote_host_or_ip
                            remote_ip = self.get_resolved_ip(resolved_host)
                    else:
                        local_ip, local_port = self.parse_address(address_data)
                        
                if parts[-1].startswith('(') and parts[-1].endswith(')'):
                    status = parts[-1].strip('()')
                elif 'LISTEN' in line:
                    status = 'LISTEN'
                else:
                    status = "N/A"
                    
                row_data = (process_name, pid, local_ip, local_port, resolved_host, remote_ip, remote_port, status)
                current_connections_set.add(row_data)

            new_connections = current_connections_set - set(self.all_connections_data.keys())
            
            if new_connections:
                self.data_queue.put(new_connections)

        except subprocess.CalledProcessError as e:
            if self.monitoring_active:
                messagebox.showerror("Error", f"Command failed with error: {e.output.decode('utf-8')}")
                self.stop_monitoring()
        except Exception as e:
            if self.monitoring_active:
                messagebox.showerror("Error", f"An unexpected error occurred: {e}")
                self.stop_monitoring()
    
    def find_item_id(self, values_tuple, tree):
        for item in tree.get_children():
            if tree.item(item, 'values') == values_tuple:
                return item
        return None

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
            if address and address != "*":
                socket.inet_aton(address)
                return True
        except socket.error:
            return False
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
        if not address_str or address_str == '*':
            return "N/A", "N/A"
        
        if ':' in address_str:
            parts = address_str.rsplit(':', 1)
            host = parts[0] if parts[0] else "localhost"
            port = self.get_numerical_port(parts[1])
            return host, port
        return address_str, "N/A"
            
    def export_to_csv(self):
        displayed_data = [self.all_connections_tree.item(item, 'values') for item in self.all_connections_tree.get_children()]
        
        if not displayed_data:
            messagebox.showwarning("No Data", "No network connections to export in the current view.")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Process", "PID", "Local IP", "Local Port", "Resolved Host", "Remote IP", "Remote Port", "Status"])
                writer.writerows(displayed_data)
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")

if __name__ == "__main__":
    if sys.platform != 'linux':
        pass
    root = tk.Tk()
    app = ProcessMonitorApp(root)
    root.mainloop()
