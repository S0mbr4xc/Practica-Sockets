import socket
import threading
from cryptography.fernet import Fernet

# Clave simétrica compartida (debe ser la misma que en el cliente)
KEY = b'L9tB8XrT_7hkTovA9uQzkBpE8T6gn15c8M6bUciTPfQ='
cipher = Fernet(KEY)

host = '127.0.0.1'
port = 55555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

print(f"Server running on {host}:{port}")

clients = []
usernames = []
message_history = []  # Lista para almacenar el historial de mensajes


def broadcast(message, exclude_client=None):
    """Envía un mensaje a todos los clientes excepto el remitente."""
    for client in clients.copy():
        if client != exclude_client:
            try:
                client.send(cipher.encrypt((message + "\n").encode('utf-8')))
            except Exception as e:
                print(f"Error al enviar mensaje: {e}")
                remove_client(client)


def remove_client(client):
    """Elimina un cliente de la lista y lo desconecta."""
    if client in clients:
        try:
            index = clients.index(client)
            username = usernames[index]
            print(f"{username} se ha desconectado.")
            broadcast(f"{username} se ha desconectado del chat.", exclude_client=client)
            clients.remove(client)
            usernames.remove(username)
        except ValueError:
            pass
    try:
        client.close()
    except Exception as e:
        print(f"Error al cerrar la conexión del cliente: {e}")


def handle_client(client):
    """Maneja los mensajes de un cliente específico."""
    try:
        encrypted_username = client.recv(1024)
        username = cipher.decrypt(encrypted_username).decode('utf-8')
        usernames.append(username)
        clients.append(client)

        print(f"{username} conectado.")
        broadcast(f"{username} se ha unido al chat.")

        # Enviar el historial de mensajes al nuevo cliente como un solo bloque
        if message_history:
            history_block = "\n".join(message_history) + "\n"  # Todos los mensajes con separador
            client.send(cipher.encrypt(history_block.encode('utf-8')))

        while True:
            try:
                encrypted_message = client.recv(1024)
                if not encrypted_message:
                    break

                message = cipher.decrypt(encrypted_message).decode('utf-8')
                print(f"Mensaje de {username}: {message}")

                message_history.append(f"{username}: {message}")

                broadcast(f"{username}: {message}")
            except Exception as e:
                print(f"Error al recibir/desencriptar mensaje de {username}: {e}")
                break

    except Exception as e:
        print(f"Error con el cliente: {e}")

    remove_client(client)


def accept_connections():
    """Acepta conexiones de nuevos clientes."""
    while True:
        try:
            client, address = server.accept()
            print(f"Conexión entrante desde {address}")
            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()
        except Exception as e:
            print(f"Error al aceptar conexiones: {e}")


if __name__ == "__main__":
    try:
        accept_connections()
    except KeyboardInterrupt:
        print("\nServidor cerrado.")
        server.close()
