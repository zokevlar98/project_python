import hashlib
from multiprocessing import Process, Queue

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

if __name__ == '__main__':
	file_paths = input("Enter the paths to the files (comma-separated): ").strip('\u202a').split(',')
	hash_type = input("Enter the hash type (md2, md4, md5, sha1, sha224, sha256, sha384, sha512): ")
	reference_hashes = input("Enter the reference hashes (comma-separated): ").split(',')

	if len(file_paths) != len(reference_hashes):
		print("Error: Number of files and reference hashes should be the same.")
		exit()

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
			print(f"An error occurred for file {file_paths[i]}: {result[1]}")
		else:
			calculated_hash = result
			print(f"Calculated hash for file {file_paths[i]} ({hash_type.upper()}): {calculated_hash}")

			if calculated_hash == reference_hashes[i]:
				print("File integrity check: Matched!")
			else:
				print("File integrity check: Not matched!")
