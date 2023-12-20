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
	file_path = input("Enter the path to the file: ").strip('\u202a')  # Strip the Unicode character
	hash_type = input("Enter the hash type (md2, md4, md5, sha1, sha224, sha256, sha384, sha512): ")
	reference_hash = input("Enter the reference hash: ")

	queue = Queue()

	process = Process(target=calculate_file_hash, args=(file_path, hash_type, queue))
	process.start()
	process.join()

	result = queue.get()

	if isinstance(result, tuple) and result[0] == 'error':
		print(f"An error occurred: {result[1]}")
	else:
		calculated_hash = result
		print(f"Calculated hash ({hash_type.upper()}): {calculated_hash}")

		if calculated_hash == reference_hash:
			print("File integrity check: Matched!")
		else:
			print("File integrity check: Not matched!")