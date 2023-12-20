from queue import Queue

# Créer une file
ma_file = Queue()

# Ajouter des éléments à la file
ma_file.put(1)
ma_file.put(2)
ma_file.put(3)

# Retirer des éléments de la file
element = ma_file.get()
print("Élément retiré de la file :", element)

# Taille de la file
taille_file = ma_file.qsize()
print("Taille de la file :", taille_file)
