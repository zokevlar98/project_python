import hashlib
from multiprocessing import Process, Queue
import tkinter as tk
from tkinter import filedialog

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
            raise ValueError("Type de hachage invalide sélectionné.")

        queue.put(file_hash)
    except Exception as e:
        queue.put(("error", str(e)))

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)

def calculate_hash_interface():
    file_path = entry_file_path.get()
    hash_type = entry_hash_type.get()
    reference_hash = entry_reference_hash.get()

    queue = Queue()

    process = Process(target=calculate_file_hash, args=(file_path, hash_type, queue))
    process.start()
    process.join()

    result = queue.get()

    if isinstance(result, tuple) and result[0] == 'error':
        result_label.config(text=f"Une erreur s'est produite : {result[1]}", fg="red")
    else:
        calculated_hash = result
        result_label.config(text=f"Hachage calculé ({hash_type.upper()}) : {calculated_hash}", fg="green")

        if calculated_hash == reference_hash:
            integrity_label.config(text="Vérification de l'intégrité du fichier : Correspondance !", fg="green")
        else:
            integrity_label.config(text="Vérification de l'intégrité du fichier : Non correspondance !", fg="red")

# Création de l'interface graphique
app = tk.Tk()
app.title("Calculateur de hachage")

# Label et Entry pour le chemin du fichier
label_file_path = tk.Label(app, text="Chemin du fichier:")
label_file_path.pack()

entry_file_path = tk.Entry(app)
entry_file_path.pack()

# Label et Entry pour le type de hachage
label_hash_type = tk.Label(app, text="Type de hachage:")
label_hash_type.pack()

entry_hash_type = tk.Entry(app)
entry_hash_type.pack()

# Label et Entry pour la référence de hachage
label_reference_hash = tk.Label(app, text="Référence de hachage:")
label_reference_hash.pack()

entry_reference_hash = tk.Entry(app)
entry_reference_hash.pack()

# Bouton pour parcourir le fichier
button_browse = tk.Button(app, text="Parcourir", command=lambda: browse_file(entry_file_path))
button_browse.pack()

# Bouton pour calculer le hachage et vérifier l'intégrité
button_calculate = tk.Button(app, text="Calculer et Vérifier", command=calculate_hash_interface)
button_calculate.pack()

# Labels pour afficher les résultats
result_label = tk.Label(app, text="Résultat:")
result_label.pack()

integrity_label = tk.Label(app, text="Vérification de l'intégrité du fichier :")
integrity_label.pack()

# Lancement de l'interface graphique
app.mainloop()
