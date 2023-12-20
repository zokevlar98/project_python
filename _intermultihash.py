import hashlib
from multiprocessing import Process, Queue
from tkinter import Tk, Label, Button, Entry, StringVar, filedialog, messagebox

def calculate_file_hash(file_path, hash_type, queue):
	try:
		with open(file_path, 'rb') as file:
			content = file.read()

		if hash_type == 'md2':
			file_hash = hashlib.md2(content).hexdigest()
		elif hash_type == 'md4':
			file_hash = hashlib.new('md4', content).hexdigest()
		elif hash_type == 'md5':
			file_hash = hashlib.md5(content).hexdigest()
		elif hash_type == 'sha1':
			file_hash = hashlib.sha1(content).hexdigest()
		elif hash_type == 'sha224':
			file_hash = hashlib.sha224(content).hexdigest()
		elif hash_type == 'sha256':
			file_hash = hashlib.sha256(content).hexdigest()
		elif hash_type == 'sha384':
			file_hash = hashlib.sha384(content).hexdigest()
		elif hash_type == 'sha512':
			file_hash = hashlib.sha512(content).hexdigest()
		else:
			raise ValueError("Invalid hash type selected.")

		queue.put(file_hash)
	except Exception as e:
		queue.put(("error", str(e)))

def process_files(file_paths, hash_type, reference_hashes):
	queues = [Queue() for _ in range(len(file_paths))]
	processes = []

	for i in range(len(file_paths)):
		process = Process(target=calculate_file_hash, args=(file_paths[i], hash_type, queues[i]))
		processes.append(process)
		process.start()

	for process in processes:
		process.join()

	for i in range(len(file_paths)):
		result = queues[i].get()

		if isinstance(result, tuple) and result[0] == 'error':
			messagebox.showerror("Error", f"An error occurred for file {file_paths[i]}: {result[1]}")
		else:
			calculated_hash = result
			messagebox.showinfo(
				"File Integrity Check",
				f"Calculated hash for file {file_paths[i]} ({hash_type.upper()}): {calculated_hash}\n"
				f"Reference hash: {reference_hashes[i]}"
			)
			if calculated_hash == reference_hashes[i]:
				messagebox.showinfo("File Integrity Check", "Matched!")
			else:
				messagebox.showwarning("File Integrity Check", "Not matched!")

def browse_file_paths(entry_var):
	file_paths = filedialog.askopenfilenames()
	entry_var.set(','.join(file_paths))

def get_user_input():
	root = Tk()
	root.title("File Integrity Check")

	file_paths_var = StringVar()
	hash_type_var = StringVar()
	reference_hashes_var = StringVar()

	Label(root, text="File Paths:").pack()
	Entry(root, textvariable=file_paths_var).pack()
	Button(root, text="Browse", command=lambda: browse_file_paths(file_paths_var)).pack()

	Label(root, text="Hash Type:").pack()
	Entry(root, textvariable=hash_type_var).pack()

	Label(root, text="Reference Hashes:").pack()
	Entry(root, textvariable=reference_hashes_var).pack()

	Button(root, text="Check Integrity", command=lambda: process_files(
		file_paths_var.get().split(','),
		hash_type_var.get(),
		reference_hashes_var.get().split(',')
	)).pack()

	root.mainloop()

if __name__ == '__main__':
	get_user_input()
