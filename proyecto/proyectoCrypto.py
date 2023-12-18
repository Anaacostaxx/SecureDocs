import tkinter as tk
from pymongo import MongoClient
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import tkinter.filedialog as filedialog
from PIL import ImageTk, Image
import tkinter.font as tkFont
import hashlib




def connect_to_mongodb(database_url, database_name):
    try:
        # Create a MongoClient to the MongoDB instance
        client = MongoClient(database_url)

        # Access the specified database (Creates it if it doesn't exist)
        db = client[database_name]

        return db  # Return the database object for further operations

    except Exception as e:
        print(f"Error connectandose a MongoDB: {e}")
        return None


#Generar una clave de cifrado
#clave = Fernet.generate_key()
#cipher_suite = Fernet(clave)

# Función para cifrar un texto
def cifrar(texto):
    return cipher_suite.encrypt(texto.encode())

# Función para descifrar un texto
def descifrar(texto_cifrado):
    return cipher_suite.decrypt(texto_cifrado).decode()
    
def register_user():
    username = username_entry.get()
    password = password_entry.get()

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username already exists
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        status_label.config(text="Username already exists!")
    else:
        # Insert the new user into the database with the hashed password
        new_user = {
            "username": username,
            "password": hashed_password,
            
        }
        users_collection.insert_one(new_user)
        status_label.config(text="Registration successful!")

def login_user():
    username = username_entry.get()
    password = password_entry.get()

    # Retrieve user details from the database based on the username
    user = users_collection.find_one({"username": username})
    if user:
        stored_password = user.get("password", "")  # Retrieve stored hashed password
        salt = user.get("salt", "")  # Retrieve the salt used for hashing

        # Hash the provided password with the retrieved salt
        hashed_password = hashlib.sha256((salt + password).encode()).hexdigest()

        # Compare the hashed passwords
        if hashed_password == stored_password:
            status_label.config(text="Login successful!")

            # Destroy existing widgets in the frame
            for widget in frame.winfo_children():
                widget.destroy()

            # Create buttons for generating keys, signing document, and encrypting document
            create_key_button = tk.Button(frame, text="Crear par de llaves", command=lambda: create_key_pair(username))
            create_key_button.grid(row=0, column=0, pady=10)

            sign_document_button = tk.Button(frame, text="Firmar un documento", command=lambda: sign_document(username))
            sign_document_button.grid(row=1, column=0, pady=10)

            encrypt_document_button = tk.Button(frame, text="Cifrar un documento", command=lambda: encrypt_document(username))
            encrypt_document_button.grid(row=2, column=0, pady=10)

        else:
            status_label.config(text="Invalid username or password!")
    else:
        status_label.config(text="Invalid username or password!")


curve = ec.SECP256R1

def create_key_pair(name):
    # Placeholder function for key pair generation using GCM
    # Replace this with your code to generate key pairs with GCM
    print("Creando par de llaves...")  # Placeholder message, replace this
    

    
    #privada
    private_key = ec.generate_private_key(curve, default_backend())
    pem_key = private_key.private_bytes( encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    Privatekey_base64 = base64.b64encode(pem_key)
    #publica
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(  encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo )
    Publickey_base64 = base64.b64encode(pem_public_key)

    #with open("/Users/ana/Crypto/proyecto/Private_"+name+".pem",'wb') as f:
     #   f.write(Privatekey_base64)
    directory = filedialog.askdirectory(title="Selecciona un directorio para guardar tu llave privada")
    if directory:
        file_path = f"{directory}/Private_{name}.pem"
        with open(file_path, 'wb') as f:
            f.write(Privatekey_base64)
            print(f"Private key saved at: {file_path}")

    user = users_collection.find_one_and_update(
        {"username": name},
        {"$set": {"public_key": Publickey_base64}}
    )

    if user:
        print("La llave pública se ha guardado en la base de datos .")
    else:
        print("Usuairo no encontrado o no se pudo actualizar la lave pública.")


# Replace 'mongodb://localhost:27017' with your MongoDB URL and 'EmpresaDB' with your database name
db_connection = connect_to_mongodb('mongodb://localhost:27017', 'EmpresaDB')
if db_connection is not None:  # Check if the database connection is successful
    users_collection = db_connection['llavero']
    root = tk.Tk()
    # Rest of the code for GUI remains unchanged
else:
    print("No se pudo conectar a la base de datos.")




    
root = tk.Toplevel()
root.title("Autenticación de usuario")
root.configure(bg="#FFFBF5")

# Canvas on the left side
canvas = tk.Canvas(root, bg="#5E95FF", height=506, width=380, bd=0, highlightthickness=0, relief="ridge")
canvas.pack(side="left")

custom_font = tkFont.Font(family="Monserrat", size=40, weight="bold")
custom_font2 = tkFont.Font(family="Monserrat", size=15, weight="normal")
# Add information to the canvas
canvas_text = "SafeDocs\n"
canvas.create_text(15, 50, anchor="nw", text=canvas_text, fill="white", font=custom_font)

canvas_text = "SafeDocs es una herramienta que permite \nfirmar electrónicamente actas de reuniones \ny redactar memorandos con opción a versiones \nconfidenciales, garantizando la validez \nde los documentos y la seguridad de la información \nsensible mediante técnicas criptográficas."
canvas.create_text(10, 150, anchor="nw", text=canvas_text, fill="white", font=custom_font2)


frame = tk.Frame(root, bg="#FFFBF5")
frame.pack(side="right", padx=150, pady=20)

image_path = '/Users/ana/Crypto/proyecto/teacher.png'
imageLogin = Image.open(image_path)
imageLogin = imageLogin.resize((90, 90))
imageLogin2 = ImageTk.PhotoImage(imageLogin)
image_label = tk.Label(frame, image=imageLogin2, bg="#FFFBF5")
image_label.pack()


custom_font3 = tkFont.Font(family="Monserrat", size=16, weight="bold")

username_label = tk.Label(frame, text="Nombre de usuario:", font=custom_font3,bg="#FFFBF5", fg="#5E95FF")
username_label.pack()

# Rounded border for username entry
username_entry = tk.Entry(frame, bd=0, bg="#DDF2FD", highlightthickness=0)
username_entry.pack()
username_entry.config(highlightbackground="#5E95FF", highlightcolor="#5E95FF", highlightthickness=2)

# Password label and entry
password_label = tk.Label(frame, text="Contraseña:", font=custom_font3,bg="#FFFBF5", fg="#5E95FF")
password_label.pack()

# Rounded border for password entry
password_entry = tk.Entry(frame, show="*", bd=0, bg="#DDF2FD", highlightthickness=0)
password_entry.pack()
password_entry.config(highlightbackground="#5E95FF", highlightcolor="#5E95FF", highlightthickness=2)

# Register and Login buttons, status label
register_button = tk.Button(frame, text="Registrarse", bg='#5E95FF',command=register_user)
register_button.pack(pady=15)

login_button = tk.Button(frame, text="Entrar", command=login_user,bg='#5E95FF')

login_button.pack()

status_label = tk.Label(frame, text="")
status_label.pack()

root.mainloop()