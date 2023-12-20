import hashlib
import tkinter as tk
def calculate_hash(file_path, hash_type):
    """Calcule le hachage d'un fichier.
    Args:
        file_path (str): Chemin du fichier.
        hash_type (str): Type de hachage (par exemple, "sha256").
    Returns:
        str: Hachage du fichier.
    """
    # Ouvrir le fichier en mode lecture binaire
    with open(file_path, "rb") as f:
        # Créer un objet de hachage
        hasher = hashlib.new(hash_type)
        # Lire le fichier par blocs et mettre à jour le hachage
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)
        # Obtenir le hachage final
        return hasher.hexdigest()
def check_integrity(file_path, hash_type, reference_hash):
    """Vérifie l'intégrité d'un fichier en comparant son hachage à un hachage de référence.
    Args:
        file_path (str): Chemin du fichier.
        hash_type (str): Type de hachage (par exemple, "sha256").
        reference_hash (str): Hachage de référence.
    Returns:
        bool: True si le fichier est intègre, False sinon.
    """
    # Calculer le hachage du fichier
    calculated_hash = calculate_hash(file_path, hash_type)
    # Comparer le hachage calculé au hachage de référence
    return calculated_hash == reference_hash
